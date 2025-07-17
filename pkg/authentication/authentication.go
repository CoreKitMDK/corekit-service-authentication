package authentication

import (
	"context"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"time"
)

type IDAL interface {
	Close()
	LoginPassword(ctx context.Context, req *LoginPasswordRequest) (*LoginPasswordResponse, error)
	LoginRefreshToken(ctx context.Context, req *LoginRefreshTokenRequest) (*LoginRefreshTokenResponse, error)
	RegisterPassword(ctx context.Context, req *RegisterPasswordRequest) (*RegisterPasswordResponse, error)
	RefreshToken(ctx context.Context, req *RefreshTokenRequest) (*RefreshTokenResponse, error)
	LogoutToken(ctx context.Context, req *LogoutTokenRequest) (*LogoutTokenResponse, error)
	LogoutRefreshToken(ctx context.Context, req *LogoutRefreshTokenRequest) (*LogoutRefreshTokenResponse, error)
	LogoutAll(ctx context.Context, req *LogoutAllRequest) (*LogoutAllResponse, error)
	GetVerificationCode(ctx context.Context, req *GetVerificationCodeRequest) (*GetVerificationCodeResponse, error)
	VerifyEntity(ctx context.Context, req *VerifyEntityRequest) (*VerifyEntityResponse, error)
	ForgotPassword(ctx context.Context, req *ForgotPasswordRequest) (*ForgotPasswordResponse, error)
	ChangePassword(ctx context.Context, req *ChangePasswordRequest) (*ChangePasswordResponse, error)
	DeleteEntity(ctx context.Context, req *DeleteEntityRequest) (*DeleteEntityResponse, error)
	GetEntityDetails(ctx context.Context, req *GetEntityDetailsRequest) (*GetEntityDetailsResponse, error)
}

type DALPostgres struct {
	db              *pgx.Conn
	tokenIssuer     string
	tokenAudience   []string
	tokenSigningKey string
}

func NewAuthenticationDALPostgres(connString string, tokenIssuer string, tokenAudience []string, tokenSigningKey string) (*DALPostgres, error) {
	conn, err := pgx.Connect(context.Background(), connString)
	if err != nil {
		return nil, err
	}
	return &DALPostgres{
		db:              conn,
		tokenIssuer:     tokenIssuer,
		tokenAudience:   tokenAudience,
		tokenSigningKey: tokenSigningKey,
	}, nil
}

func (dal *DALPostgres) Close() {
	err := dal.db.Close(context.Background())
	if err != nil {
		return
	}
}

func (dal *DALPostgres) LoginPassword(ctx context.Context, req *LoginPasswordRequest) (*LoginPasswordResponse, error) {
	query1 := `SELECT e.id, elmp.password_hash FROM entities e 
    			JOIN entity_login_methods elm ON e.id = elm.entity_id
    			JOIN entity_login_method_password elmp  ON elm.method_id = elmp.id
    			WHERE elm.method_type = 'entity_login_method_password' AND elmp.identifier = $1 
                AND e.active = true AND elmp.active = true;`

	rows, err := dal.db.Query(ctx, query1, req.Identifier)
	if err != nil {
		return &LoginPasswordResponse{Valid: false, Error: err.Error()}, err
	}
	defer rows.Close()

	passwordHash := ""
	entityIDString := ""
	for rows.Next() {
		err := rows.Scan(&entityIDString, &passwordHash)
		if err != nil {
			return &LoginPasswordResponse{Valid: false, Error: err.Error()}, err
		}
	}

	entityID, err := uuid.Parse(entityIDString)
	if err != nil {
		return &LoginPasswordResponse{Valid: false, Error: err.Error()}, err
	}

	isPasswordCorrect := IsHashSameAsUnhashedString(passwordHash, req.Password)
	if !isPasswordCorrect {
		return &LoginPasswordResponse{Valid: false, Error: "Incorrect password"}, nil
	}

	tx, err := dal.db.Begin(ctx)
	if err != nil {
		return &LoginPasswordResponse{Valid: false, Error: err.Error()}, err
	}
	defer tx.Rollback(ctx)

	randomRefreshTokenId, err := GetRandomAlphanumericString(32)
	if err != nil {
		return &LoginPasswordResponse{Valid: false, Error: err.Error()}, err
	}

	refreshTokenExpiresAt := time.Now().UTC().Add(time.Hour * 24 * 30)
	refreshToken, err := GenerateJWT(dal.tokenIssuer, entityID.String(), dal.tokenAudience, refreshTokenExpiresAt, time.Now().UTC(), time.Now().UTC(), randomRefreshTokenId, dal.tokenSigningKey)
	if err != nil {
		return &LoginPasswordResponse{Valid: false, Error: err.Error()}, err
	}

	entityRefreshTokenIdString := ""
	query2 := `INSERT INTO entity_refresh_tokens (entity_id, token, token_random_id, expires_at) VALUES ($1, $2, $3, $4)  RETURNING id;`
	err = tx.QueryRow(ctx, query2, entityID, refreshToken, randomRefreshTokenId, refreshTokenExpiresAt.Unix()).Scan(&entityRefreshTokenIdString)
	if err != nil {
		return &LoginPasswordResponse{Valid: false, Error: err.Error()}, err
	}

	randomTokenId, err := GetRandomAlphanumericString(32)
	if err != nil {
		return &LoginPasswordResponse{Valid: false, Error: err.Error()}, err
	}

	tokenExpiresAt := time.Now().UTC().Add(time.Minute * 15)
	token, err := GenerateJWT(dal.tokenIssuer, entityID.String(), dal.tokenAudience, refreshTokenExpiresAt, time.Now().UTC(), time.Now().UTC(), randomTokenId, dal.tokenSigningKey)
	if err != nil {
		return &LoginPasswordResponse{Valid: false, Error: err.Error()}, err
	}

	query3 := `INSERT INTO entity_tokens (entity_id, token, token_random_id, refresh_token_id, expires_at) VALUES ($1, $2, $3, $4,  $5);`
	_, err = tx.Exec(ctx, query3, entityID, token, randomTokenId, entityRefreshTokenIdString, tokenExpiresAt.Unix())

	if err = tx.Commit(ctx); err != nil {
		return &LoginPasswordResponse{Valid: false, Error: err.Error()}, err
	}

	return &LoginPasswordResponse{
		Entity:                entityID,
		Token:                 token,
		TokenExpiresAt:        tokenExpiresAt.Unix(),
		RefreshToken:          refreshToken,
		RefreshTokenExpiresAt: refreshTokenExpiresAt.Unix(),
		Valid:                 true,
		Error:                 "",
	}, nil
}

func (dal *DALPostgres) LoginRefreshToken(ctx context.Context, req *LoginRefreshTokenRequest) (*LoginRefreshTokenResponse, error) {

	parsedRefreshToken, err := VerifyJWT(req.RefreshToken, dal.tokenSigningKey)
	if err != nil {
		return &LoginRefreshTokenResponse{Valid: false, Error: err.Error()}, err
	}

	err = ValidateJWT(parsedRefreshToken)
	if err != nil {
		return &LoginRefreshTokenResponse{Valid: false, Error: err.Error()}, err
	}

	query1 := `SELECT id, token, token_random_id FROM entity_refresh_tokens WHERE entity_id = $1 AND token = $2 AND active = true AND expires_at > current_epoch();`
	rows, err := dal.db.Query(ctx, query1, req.Entity, req.RefreshToken)
	if err != nil {
		return &LoginRefreshTokenResponse{Valid: false, Error: err.Error()}, err
	}
	defer rows.Close()

	refreshTokenIdString := ""
	refreTokenRandomId := ""
	refreshTokenString := ""
	for rows.Next() {
		err := rows.Scan(&refreshTokenIdString, &refreshTokenString, &refreTokenRandomId)
		if err != nil {
			return &LoginRefreshTokenResponse{Valid: false, Error: err.Error()}, err
		}
	}

	randomTokenId, err := GetRandomAlphanumericString(32)
	if err != nil {
		return &LoginRefreshTokenResponse{Valid: false, Error: err.Error()}, err
	}

	refreshTokenId, err := uuid.Parse(refreshTokenIdString)
	if err != nil {
		return &LoginRefreshTokenResponse{Valid: false, Error: err.Error()}, err
	}

	tokenExpiresAt := time.Now().UTC().Add(time.Minute * 15)
	token, err := GenerateJWT(dal.tokenIssuer, req.Entity.String(), dal.tokenAudience, tokenExpiresAt, time.Now().UTC(), time.Now().UTC(), randomTokenId, dal.tokenSigningKey)
	if err != nil {
		return &LoginRefreshTokenResponse{Valid: false, Error: err.Error()}, err
	}

	tx, err := dal.db.Begin(ctx)
	if err != nil {
		return &LoginRefreshTokenResponse{Valid: false, Error: err.Error()}, err
	}
	defer tx.Rollback(ctx)

	query2 := `INSERT INTO entity_tokens (entity_id, token, token_random_id, refresh_token_id, expires_at) VALUES ($1, $2, $3, $4,  $5);`
	_, err = tx.Exec(ctx, query2, req.Entity, token, randomTokenId, refreshTokenId, tokenExpiresAt.Unix())

	if err = tx.Commit(ctx); err != nil {
		return &LoginRefreshTokenResponse{Valid: false, Error: err.Error()}, err
	}

	return &LoginRefreshTokenResponse{
		Entity:         req.Entity,
		Token:          token,
		TokenExpiresAt: tokenExpiresAt.Unix(),
		Valid:          true,
		Error:          "",
	}, nil
}

func (dal *DALPostgres) RegisterPassword(ctx context.Context, req *RegisterPasswordRequest) (*RegisterPasswordResponse, error) {
	query1 := `SELECT id FROM entities WHERE primary_email = $1;`

	rows, err := dal.db.Query(ctx, query1, req.PrimaryEmail)
	if err != nil {
		return &RegisterPasswordResponse{Valid: false, Error: err.Error()}, err
	}
	defer rows.Close()

	var entityID uuid.UUID
	for rows.Next() {
		err := rows.Scan(&entityID)
		if err != nil {
			return &RegisterPasswordResponse{Valid: false, Error: err.Error()}, err
		}
	}

	if entityID != uuid.Nil {
		return &RegisterPasswordResponse{Valid: false, Error: "Existing email"}, nil
	}

	tx, err := dal.db.Begin(ctx)
	if err != nil {
		return &RegisterPasswordResponse{Valid: false, Error: err.Error()}, err
	}
	defer tx.Rollback(ctx)

	insertedEntityID := ""
	query2 := `INSERT INTO entities (primary_email, primary_phone, public_identifier) VALUES ($1, $2, $3) RETURNING id;`
	err = tx.QueryRow(ctx, query2, req.PrimaryEmail, req.PrimaryPhone, req.PublicIdentifier).Scan(&insertedEntityID)
	if err != nil {
		return &RegisterPasswordResponse{Valid: false, Error: err.Error()}, err
	}

	entityID, err = uuid.Parse(insertedEntityID)
	if err != nil {
		return &RegisterPasswordResponse{Valid: false, Error: err.Error()}, err
	}

	passwordHash, err := HashString(req.Password)
	if err != nil {
		return &RegisterPasswordResponse{Valid: false, Error: err.Error()}, err
	}

	EntityLoginMethodPasswordIdString := ""
	query3 := `INSERT INTO entity_login_method_password (identifier, password_hash) VALUES ($1, $2) RETURNING id;`
	err = tx.QueryRow(ctx, query3, req.PrimaryEmail, passwordHash).Scan(&EntityLoginMethodPasswordIdString)
	if err != nil {
		return &RegisterPasswordResponse{Valid: false, Error: err.Error()}, err
	}

	EntityLoginMethodPasswordId, err := uuid.Parse(EntityLoginMethodPasswordIdString)
	if err != nil {
		return &RegisterPasswordResponse{Valid: false, Error: err.Error()}, err
	}

	query4 := `INSERT INTO entity_login_methods (entity_id, method_id, method_type) VALUES ($1, $2, 'entity_login_method_password');`
	_, err = tx.Exec(ctx, query4, entityID, EntityLoginMethodPasswordId)
	if err != nil {
		return &RegisterPasswordResponse{Valid: false, Error: err.Error()}, err
	}

	randomRefreshTokenId, err := GetRandomAlphanumericString(32)
	if err != nil {
		return &RegisterPasswordResponse{Valid: false, Error: err.Error()}, err
	}

	refreshTokenExpiresAt := time.Now().UTC().Add(time.Hour * 24 * 30)
	refreshToken, err := GenerateJWT(dal.tokenIssuer, entityID.String(), dal.tokenAudience, refreshTokenExpiresAt, time.Now().UTC(), time.Now().UTC(), randomRefreshTokenId, dal.tokenSigningKey)
	if err != nil {
		return &RegisterPasswordResponse{Valid: false, Error: err.Error()}, err
	}

	entityRefreshTokenIdString := ""
	query5 := `INSERT INTO entity_refresh_tokens (entity_id, token, token_random_id, expires_at) VALUES ($1, $2, $3, $4) RETURNING id;`
	err = tx.QueryRow(ctx, query5, entityID, refreshToken, randomRefreshTokenId, refreshTokenExpiresAt.Unix()).Scan(&entityRefreshTokenIdString)
	if err != nil {
		return &RegisterPasswordResponse{Valid: false, Error: err.Error()}, err
	}

	randomTokenId, err := GetRandomAlphanumericString(32)
	if err != nil {
		return &RegisterPasswordResponse{Valid: false, Error: err.Error()}, err
	}

	tokenExpiresAt := time.Now().UTC().Add(time.Minute * 15)
	token, err := GenerateJWT(dal.tokenIssuer, entityID.String(), dal.tokenAudience, refreshTokenExpiresAt, time.Now().UTC(), time.Now().UTC(), randomTokenId, dal.tokenSigningKey)
	if err != nil {
		return &RegisterPasswordResponse{Valid: false, Error: err.Error()}, err
	}

	query6 := `INSERT INTO entity_tokens (entity_id, token, token_random_id, refresh_token_id, expires_at) VALUES ($1, $2, $3, $4,  $5);`
	_, err = tx.Exec(ctx, query6, entityID, token, randomTokenId, entityRefreshTokenIdString, tokenExpiresAt.Unix())

	if err = tx.Commit(ctx); err != nil {
		return &RegisterPasswordResponse{Valid: false, Error: err.Error()}, err
	}

	return &RegisterPasswordResponse{
		Entity:                entityID,
		Token:                 token,
		TokenExpiresAt:        tokenExpiresAt.Unix(),
		RefreshToken:          refreshToken,
		RefreshTokenExpiresAt: refreshTokenExpiresAt.Unix(),
		Valid:                 true,
		Error:                 "",
	}, nil
}

func (dal *DALPostgres) RefreshToken(ctx context.Context, req *RefreshTokenRequest) (*RefreshTokenResponse, error) {

	parsedRefreshTokenCheck, err := VerifyJWT(req.RefreshToken, dal.tokenSigningKey)
	if err != nil {
		return &RefreshTokenResponse{Valid: false, Error: err.Error()}, err
	}

	err = ValidateJWT(parsedRefreshTokenCheck)
	if err != nil {
		return &RefreshTokenResponse{Valid: false, Error: err.Error()}, err
	}

	query1 := `SELECT id, token, token_random_id FROM entity_refresh_tokens WHERE entity_id = $1 AND token = $2 AND active = true AND expires_at > current_epoch();`

	rows, err := dal.db.Query(ctx, query1, req.Entity, req.RefreshToken)
	if err != nil {
		return &RefreshTokenResponse{Valid: false, Error: err.Error()}, err
	}
	defer rows.Close()

	refreshTokenId := ""
	refreshToken := ""
	randomRefreshTokenId := ""
	for rows.Next() {
		err := rows.Scan(&refreshTokenId, &refreshToken, &randomRefreshTokenId)
		if err != nil {
			return &RefreshTokenResponse{Valid: false, Error: err.Error()}, err
		}
	}

	refreshTokenUUID, err := uuid.Parse(refreshTokenId)
	if err != nil {
		return &RefreshTokenResponse{Valid: false, Error: err.Error()}, err
	}

	parsedRefreshToken, err := VerifyJWT(refreshToken, dal.tokenSigningKey)
	if err != nil {
		return &RefreshTokenResponse{Valid: false, Error: err.Error()}, err
	}

	err = ValidateJWT(parsedRefreshToken)
	if err != nil {
		return &RefreshTokenResponse{Valid: false, Error: err.Error()}, err
	}

	randomTokenId, err := GetRandomAlphanumericString(32)
	if err != nil {
		return &RefreshTokenResponse{Valid: false, Error: err.Error()}, err
	}

	expiresAt := time.Now().UTC().Add(time.Minute * 15)
	token, err := GenerateJWT(dal.tokenIssuer, req.Entity.String(), dal.tokenAudience, expiresAt, time.Now().UTC(), time.Now().UTC(), randomTokenId, dal.tokenSigningKey)
	if err != nil {
		return &RefreshTokenResponse{Valid: false, Error: err.Error()}, err
	}

	tx, err := dal.db.Begin(ctx)
	if err != nil {
		return &RefreshTokenResponse{Valid: false, Error: err.Error()}, err
	}
	defer tx.Rollback(ctx)

	query2 := `INSERT INTO entity_tokens (entity_id, token, token_random_id, refresh_token_id, expires_at) VALUES ($1, $2, $3, $4,  $5);`
	_, err = tx.Exec(ctx, query2, req.Entity, token, randomTokenId, refreshTokenUUID, expiresAt.Unix())
	if err != nil {
		return &RefreshTokenResponse{Valid: false, Error: err.Error()}, err
	}

	if err = tx.Commit(ctx); err != nil {
		return &RefreshTokenResponse{Valid: false, Error: err.Error()}, err
	}

	return &RefreshTokenResponse{
		Entity:         req.Entity,
		Token:          token,
		TokenExpiresAt: expiresAt.Unix(),
		Valid:          true,
		Error:          "",
	}, nil
}

func (dal *DALPostgres) LogoutToken(ctx context.Context, req *LogoutTokenRequest) (*LogoutTokenResponse, error) {
	query1 := `SELECT id FROM entity_tokens WHERE entity_id = $1 AND token = $2 AND active = true;`

	rows, err := dal.db.Query(ctx, query1, req.Entity, req.Token)
	if err != nil {
		return &LogoutTokenResponse{Valid: false, Error: err.Error()}, err
	}
	defer rows.Close()

	logoutTokenResponse := &LogoutTokenResponse{Valid: true, Error: ""}
	id := ""

	for rows.Next() {
		err := rows.Scan(&id)
		if err != nil {
			return &LogoutTokenResponse{Valid: false, Error: err.Error()}, err
		}
	}

	tokenUUID, err := uuid.Parse(id)
	if err != nil {
		return &LogoutTokenResponse{Valid: false, Error: err.Error()}, err
	}

	tx, err := dal.db.Begin(ctx)
	if err != nil {
		return &LogoutTokenResponse{Valid: false, Error: err.Error()}, err
	}
	defer tx.Rollback(ctx)

	query2 := `UPDATE entity_tokens SET active = false, revoked_at = current_epoch() WHERE id = $1;`
	_, err = tx.Exec(ctx, query2, tokenUUID)
	if err != nil {
		return &LogoutTokenResponse{Valid: false, Error: err.Error()}, err
	}

	if err = tx.Commit(ctx); err != nil {
		return &LogoutTokenResponse{Valid: false, Error: err.Error()}, err
	}

	logoutTokenResponse.Entity = req.Entity
	logoutTokenResponse.Valid = true
	logoutTokenResponse.Error = ""
	return logoutTokenResponse, nil
}

func (dal *DALPostgres) LogoutRefreshToken(ctx context.Context, req *LogoutRefreshTokenRequest) (*LogoutRefreshTokenResponse, error) {
	query1 := `SELECT id FROM entity_refresh_tokens WHERE entity_id = $1 AND token = $2 AND active = true;`

	rows, err := dal.db.Query(ctx, query1, req.Entity, req.RefreshToken)
	if err != nil {
		return &LogoutRefreshTokenResponse{Valid: false, Error: err.Error()}, err
	}
	defer rows.Close()

	logoutRefreshTokenResponse := &LogoutRefreshTokenResponse{Valid: true, Error: ""}
	id := ""

	for rows.Next() {
		err := rows.Scan(&id)
		if err != nil {
			return &LogoutRefreshTokenResponse{Valid: false, Error: err.Error()}, err
		}
	}

	refreshTokenUUID, err := uuid.Parse(id)
	if err != nil {
		return &LogoutRefreshTokenResponse{Valid: false, Error: err.Error()}, err
	}

	tx, err := dal.db.Begin(ctx)
	if err != nil {
		return &LogoutRefreshTokenResponse{Valid: false, Error: err.Error()}, err
	}
	defer tx.Rollback(ctx)

	query2 := `UPDATE entity_refresh_tokens SET active = false, revoked_at = current_epoch() WHERE id = $1;`
	_, err = tx.Exec(ctx, query2, refreshTokenUUID)
	if err != nil {
		return &LogoutRefreshTokenResponse{Valid: false, Error: err.Error()}, err
	}

	if err = tx.Commit(ctx); err != nil {
		return &LogoutRefreshTokenResponse{Valid: false, Error: err.Error()}, err
	}

	logoutRefreshTokenResponse.Entity = req.Entity
	logoutRefreshTokenResponse.Valid = true
	logoutRefreshTokenResponse.Error = ""
	return logoutRefreshTokenResponse, nil
}

func (dal *DALPostgres) LogoutAll(ctx context.Context, req *LogoutAllRequest) (*LogoutAllResponse, error) {

	tx, err := dal.db.Begin(ctx)
	if err != nil {
		return &LogoutAllResponse{Valid: false, Error: err.Error()}, err
	}
	defer tx.Rollback(ctx)

	query1 := `UPDATE entity_tokens SET active = false, revoked_at = current_epoch() WHERE entity_id = $1;`
	_, err = tx.Exec(ctx, query1, req.Entity)
	if err != nil {
		return &LogoutAllResponse{Valid: false, Error: err.Error()}, err
	}

	query2 := `UPDATE entity_refresh_tokens SET active = false, revoked_at = current_epoch() WHERE entity_id = $1;`
	_, err = tx.Exec(ctx, query2, req.Entity)
	if err != nil {
		return &LogoutAllResponse{Valid: false, Error: err.Error()}, err
	}

	if err = tx.Commit(ctx); err != nil {
		return &LogoutAllResponse{Valid: false, Error: err.Error()}, err
	}

	return &LogoutAllResponse{
		Entity: req.Entity,
		Valid:  true,
		Error:  "",
	}, nil
}

func (dal *DALPostgres) GetVerificationCode(ctx context.Context, req *GetVerificationCodeRequest) (*GetVerificationCodeResponse, error) {

	tx, err := dal.db.Begin(ctx)
	if err != nil {
		return &GetVerificationCodeResponse{Valid: false, Error: err.Error()}, err
	}
	defer tx.Rollback(ctx)

	verificationToken, err := GetRandomAlphanumericString(32)
	if err != nil {
		return &GetVerificationCodeResponse{Valid: false, Error: err.Error()}, err
	}

	query1 := `UPDATE entities SET verification_token = $1, verification_token_expires_at = current_epoch() + $2 WHERE id = $3;`
	_, err = tx.Exec(ctx, query1, verificationToken, 15*60, req.Entity)
	if err != nil {
		return &GetVerificationCodeResponse{Valid: false, Error: err.Error()}, err
	}

	if err = tx.Commit(ctx); err != nil {
		return &GetVerificationCodeResponse{Valid: false, Error: err.Error()}, err
	}

	return &GetVerificationCodeResponse{
		req.Entity,
		verificationToken,
		true,
		"",
	}, nil
}

func (dal *DALPostgres) VerifyEntity(ctx context.Context, req *VerifyEntityRequest) (*VerifyEntityResponse, error) {

	query1 := `SELECT id FROM entities WHERE id = $1 AND active = true AND verification_token = $2 AND verification_token_expires_at > current_epoch();`

	rows, err := dal.db.Query(ctx, query1, req.Entity, req.Code)
	if err != nil {
		return &VerifyEntityResponse{Valid: false, Error: err.Error()}, err
	}
	defer rows.Close()

	var entityID uuid.UUID
	for rows.Next() {
		err := rows.Scan(&entityID)
		if err != nil {
			return &VerifyEntityResponse{Valid: false, Error: err.Error()}, err
		}
	}

	if entityID == uuid.Nil {
		return &VerifyEntityResponse{Valid: false, Error: "Not found"}, nil
	}

	tx, err := dal.db.Begin(ctx)
	if err != nil {
		return &VerifyEntityResponse{Valid: false, Error: err.Error()}, err
	}
	defer tx.Rollback(ctx)

	query2 := `UPDATE entities SET is_verified = true WHERE id = $1;`
	_, err = tx.Exec(ctx, query2, entityID)
	if err != nil {
		return &VerifyEntityResponse{Valid: false, Error: err.Error()}, err
	}

	if err = tx.Commit(ctx); err != nil {
		return &VerifyEntityResponse{Valid: false, Error: err.Error()}, err
	}

	return &VerifyEntityResponse{
		entityID,
		true,
		"",
	}, nil
}

func (dal *DALPostgres) ForgotPassword(ctx context.Context, req *ForgotPasswordRequest) (*ForgotPasswordResponse, error) {
	query1 := `SELECT id FROM entities WHERE primary_email = $1;`

	rows, err := dal.db.Query(ctx, query1, req.PrimaryEmail)
	if err != nil {
		return &ForgotPasswordResponse{Valid: false, Error: err.Error()}, err
	}
	defer rows.Close()

	var entityID uuid.UUID
	for rows.Next() {
		err := rows.Scan(&entityID)
		if err != nil {
			return &ForgotPasswordResponse{Valid: false, Error: err.Error()}, err
		}
	}

	if entityID == uuid.Nil {
		return &ForgotPasswordResponse{Valid: false, Error: "Not found"}, nil
	}

	tx, err := dal.db.Begin(ctx)
	if err != nil {
		return &ForgotPasswordResponse{Valid: false, Error: err.Error()}, err
	}
	defer tx.Rollback(ctx)

	passwordResetToken, err := GetRandomAlphanumericString(32)
	if err != nil {
		return &ForgotPasswordResponse{Valid: false, Error: err.Error()}, err
	}

	query2 := `UPDATE entity_login_method_password SET password_reset_token = $1, password_reset_token_expires_at = current_epoch() + $2 
					WHERE id = (
					    SELECT elmp.id FROM entity_login_methods elm JOIN entity_login_method_password elmp ON elm.method_id = elmp.id 
						WHERE elm.active = true and elm.method_type = 'entity_login_method_password' and elm.entity_id = $3 LIMIT 1
					);`
	_, err = tx.Exec(ctx, query2, passwordResetToken, 15*60, entityID)
	if err != nil {
		return &ForgotPasswordResponse{Valid: false, Error: err.Error()}, err
	}

	if err = tx.Commit(ctx); err != nil {
		return &ForgotPasswordResponse{Valid: false, Error: err.Error()}, err
	}

	return &ForgotPasswordResponse{
		entityID,
		passwordResetToken,
		true,
		"",
	}, nil
}

func (dal *DALPostgres) ChangePassword(ctx context.Context, req *ChangePasswordRequest) (*ChangePasswordResponse, error) {
	query1 := `SELECT e.id, elmp.id 
		FROM entities e JOIN entity_login_methods elm ON e.id = elm.entity_id 
		JOIN entity_login_method_password elmp ON elm.method_id = elmp.id
	    WHERE e.active = true AND elm.active = true AND elmp.active = true and elm.method_type like 'entity_login_method_password'
			AND e.primary_email = $1 AND elmp.password_reset_token = $2 AND elmp.password_reset_token_expires_at > current_epoch();`

	rows, err := dal.db.Query(ctx, query1, req.PrimaryEmail, req.PasswordResetToken)
	if err != nil {
		return &ChangePasswordResponse{Valid: false, Error: err.Error()}, err
	}
	defer rows.Close()

	var entityIDString string
	var entityLoginPasswordIDString string

	for rows.Next() {
		err := rows.Scan(&entityIDString, &entityLoginPasswordIDString)
		if err != nil {
			return &ChangePasswordResponse{Valid: false, Error: err.Error()}, err
		}
	}

	entityID, err := uuid.Parse(entityIDString)
	if err != nil {
		return &ChangePasswordResponse{Valid: false, Error: err.Error()}, err
	}

	entityLoginPasswordID, err := uuid.Parse(entityLoginPasswordIDString)
	if err != nil {
		return &ChangePasswordResponse{Valid: false, Error: err.Error()}, err
	}

	if entityID == uuid.Nil {
		return &ChangePasswordResponse{Valid: false, Error: "Not found"}, nil
	}

	tx, err := dal.db.Begin(ctx)
	if err != nil {
		return &ChangePasswordResponse{Valid: false, Error: err.Error()}, err
	}
	defer tx.Rollback(ctx)

	hashedPassword, err := HashString(req.Password)
	if err != nil {
		return &ChangePasswordResponse{Valid: false, Error: err.Error()}, err
	}

	query2 := `UPDATE entity_login_method_password SET password_hash = $1, password_reset_token = NULL, password_reset_token_expires_at = 0 WHERE id = $2;`

	_, err = tx.Exec(ctx, query2, hashedPassword, entityLoginPasswordID)
	if err != nil {
		return &ChangePasswordResponse{Valid: false, Error: err.Error()}, err
	}

	query3 := `UPDATE entity_tokens SET active = false, revoked_at = current_epoch() WHERE entity_id = $1;`
	_, err = tx.Exec(ctx, query3, entityID)
	if err != nil {
		return &ChangePasswordResponse{Valid: false, Error: err.Error()}, err
	}

	query4 := `UPDATE entity_refresh_tokens SET active = false, revoked_at = current_epoch() WHERE entity_id = $1;`
	_, err = tx.Exec(ctx, query4, entityID)
	if err != nil {
		return &ChangePasswordResponse{Valid: false, Error: err.Error()}, err
	}

	if err = tx.Commit(ctx); err != nil {
		return &ChangePasswordResponse{Valid: false, Error: err.Error()}, err
	}

	return &ChangePasswordResponse{
		Entity: entityID,
		Valid:  true,
		Error:  "",
	}, nil
}

func (dal *DALPostgres) DeleteEntity(ctx context.Context, req *DeleteEntityRequest) (*DeleteEntityResponse, error) {
	tx, err := dal.db.Begin(ctx)
	if err != nil {
		return &DeleteEntityResponse{Valid: false, Error: err.Error()}, err
	}
	defer tx.Rollback(ctx)

	query1 := `UPDATE entities SET active = false, deleted_at = current_epoch() WHERE id = $1;`
	_, err = tx.Exec(ctx, query1, req.Entity)
	if err != nil {
		return &DeleteEntityResponse{Valid: false, Error: err.Error()}, err
	}

	query2 := `INSERT INTO entity_delete_reasons (reason) VALUES ($1);`
	_, err = tx.Exec(ctx, query2, req.Reason)
	if err != nil {
		return &DeleteEntityResponse{Valid: false, Error: err.Error()}, err
	}

	if err = tx.Commit(ctx); err != nil {
		return &DeleteEntityResponse{Valid: false, Error: err.Error()}, err
	}

	return &DeleteEntityResponse{Valid: true, Error: ""}, nil
}

func (dal *DALPostgres) GetEntityDetails(ctx context.Context, req *GetEntityDetailsRequest) (*GetEntityDetailsResponse, error) {
	query := `SELECT id, primary_email, primary_phone, is_verified, verification_token, verification_token_expires_at, public_identifier, active, created_at, deleted_at 
			  FROM entities WHERE active = true AND id = $1;`

	rows, err := dal.db.Query(ctx, query, req.Entity)
	if err != nil {
		return &GetEntityDetailsResponse{Valid: false, Error: err.Error()}, err
	}
	defer rows.Close()

	getUserDetailsResponse := &GetEntityDetailsResponse{Valid: true, Error: ""}
	for rows.Next() {
		var entity Entity
		err := rows.Scan(&entity.ID, &entity.PrimaryEmail, &entity.PrimaryPhone, &entity.IsVerified, &entity.VerificationToken, &entity.VerificationTokenExpiresAt, &entity.PublicIdentifier, &entity.Active, &entity.CreatedAt, &entity.DeletedAt)
		if err != nil {
			return &GetEntityDetailsResponse{Valid: false, Error: err.Error()}, err
		}
		getUserDetailsResponse.Entity = &entity
		return getUserDetailsResponse, nil
	}

	getUserDetailsResponse.Valid = false
	getUserDetailsResponse.Error = "Not found"

	return getUserDetailsResponse, nil
}
