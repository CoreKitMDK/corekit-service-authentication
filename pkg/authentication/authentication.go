package authentication

import (
	"context"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type DAL struct {
	db *pgx.Conn
}

func NewAuthenticationDAL(connString string) (*DAL, error) {
	conn, err := pgx.Connect(context.Background(), connString)
	if err != nil {
		return nil, err
	}
	return &DAL{db: conn}, nil
}

func (dal *DAL) Close() {
	err := dal.db.Close(context.Background())
	if err != nil {
		return
	}
}

func (dal *DAL) LoginPassword(req *LoginPasswordRequest) (*LoginPasswordResponse, error) {
	return nil, nil
}

func (dal *DAL) LoginRefreshToken(req *LoginRefreshTokenRequest) (*LoginRefreshTokenResponse, error) {
	return nil, nil
}

func (dal *DAL) RegisterPassword(req *RegisterPasswordRequest) (*RegisterPasswordResponse, error) {
	return nil, nil
}

func (dal *DAL) RefreshToken(req *RefreshTokenRequest) (*RefreshTokenResponse, error) {
	return nil, nil
}

func (dal *DAL) LogoutToken(req *LogoutTokenRequest) (*LogoutTokenResponse, error) {
	return nil, nil
}

func (dal *DAL) LogoutRefreshToken(req *LogoutRefreshTokenRequest) (*LogoutRefreshTokenResponse, error) {
	return nil, nil
}

func (dal *DAL) LogoutAll(ctx context.Context, req *LogoutAllRequest) (*LogoutAllResponse, error) {

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

func (dal *DAL) GetVerificationCode(ctx context.Context, req *GetVerificationCodeRequest) (*GetVerificationCodeResponse, error) {

	tx, err := dal.db.Begin(ctx)
	if err != nil {
		return &GetVerificationCodeResponse{Valid: false, Error: err.Error()}, err
	}
	defer tx.Rollback(ctx)

	verificationToken, err := GetRandomAlphanumericString(32)
	if err != nil {
		return &GetVerificationCodeResponse{Valid: false, Error: err.Error()}, err
	}

	query1 := `UPDATE entity SET verification_token = $1, verification_token_expires_at = current_epoch() + $2 WHERE entity_id = $3;`
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

func (dal *DAL) VerifyEntity(ctx context.Context, req *VerifyEntityRequest) (*VerifyEntityResponse, error) {

	query1 := `SELECT id FROM entity WHERE id = $1 AND active = true AND verification_token = $2 AND verification_token_expires_at > current_epoch();`

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

	query2 := `UPDATE entity SET is_verified = true WHERE entity_id = $1;`
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

func (dal *DAL) ForgotPassword(ctx context.Context, req *ForgotPasswordRequest) (*ForgotPasswordResponse, error) {
	query1 := `SELECT id FROM entity WHERE primary_email = $1;`

	rows, err := dal.db.Query(context.Background(), query1, req.PrimaryEmail)
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

	query2 := `UPDATE entity_login_method_password SET password_reset_token = $1, password_reset_token_expires_at = current_epoch() + $2 WHERE entity_id = $3;`
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

func (dal *DAL) ChangePassword(ctx context.Context, req *ChangePasswordRequest) (*ChangePasswordResponse, error) {
	query1 := `SELECT e.id, elmp.id 
		FROM entities e JOIN entity_login_methods elm ON e.id = elm.entity_id 
		JOIN entity_login_methods_password elmp ON elm.method_id = elmp.id
	    WHERE e.active = true AND elm.active = true AND elmp.active = true and elm.method_type like 'entity_login_method_password'
			AND e.primary_email = $1 elmp.password_reset_token = $2 AND elmp.password_reset_token_expires_at > current_epoch();`

	rows, err := dal.db.Query(context.Background(), query1, req.PrimaryEmail, req.PasswordResetToken)
	if err != nil {
		return &ChangePasswordResponse{Valid: false, Error: err.Error()}, err
	}
	defer rows.Close()

	var entityID uuid.UUID
	var entityLoginPasswordID uuid.UUID

	for rows.Next() {
		var entity Entity
		err := rows.Scan(&entity.ID, &entityLoginPasswordID)
		if err != nil {
			return &ChangePasswordResponse{Valid: false, Error: err.Error()}, err
		}
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

	query2 := `UPDATE entity_login_methods SET password_hash = $1, password_reset_token = NULL, password_reset_token_expires_at = 0 WHERE id = $2;`
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

func (dal *DAL) DeleteEntity(ctx context.Context, req DeleteEntityRequest) (*DeleteEntityResponse, error) {
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

func (dal *DAL) GetEntityDetails(req *GetEntityDetailsRequest) (*GetEntityDetailsResponse, error) {
	query := `SELECT id, primary_email, primary_phone, is_verified, verification_token, verification_token_expires_at, public_identifier, active, created_at, deleted_at 
			  FROM entities WHERE active = true AND id = $1;`

	rows, err := dal.db.Query(context.Background(), query, req.Entity)
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
