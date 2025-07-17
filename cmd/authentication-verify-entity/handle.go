package function

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/CoreKitMDK/corekit-service-authentication/v2/pkg/authentication"
	"net/http"

	"github.com/CoreKitMDK/corekit-service-core/v2/pkg/core"
	"github.com/CoreKitMDK/corekit-service-logger/v2/pkg/logger"
)

var (
	Core, _ = core.NewCore()
	dal     *authentication.DALPostgres
)

func Handle(w http.ResponseWriter, r *http.Request) {
	trace := Core.Tracing.TraceHttpRequest(r).Start()
	defer trace.TraceHttpResponseWriter(w).End()

	if dal == nil {
		connStr, err := Core.Configuration.Get("internal-authentication-db")
		if err != nil {
			Core.Logger.Log(logger.FATAL, "failed to get database connection string: "+err.Error())
		}

		dal, err = authentication.NewAuthenticationDALPostgres(connStr, "https://test.com", make([]string, 0), "1234")
		if err != nil {
			Core.Logger.Log(logger.FATAL, "failed to initialize Authentication DAL: "+err.Error())
		}
	}

	caller := r.Header.Get("Caller")

	var req authentication.VerifyEntityRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		Core.Logger.Log(logger.ERROR, "failed to decode request body for caller: "+caller+", error: "+err.Error())
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	resp, err := dal.VerifyEntity(context.Background(), &req)
	if err != nil {
		Core.Logger.Log(logger.ERROR, "failed to get rights for caller: "+caller+", error: "+err.Error())
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	if !resp.Valid {
		Core.Logger.Log(logger.WARN, "LoginPassword operation was not valid for caller: "+caller+", error: "+resp.Error)
		http.Error(w, resp.Error, http.StatusBadRequest)
		return
	}

	respBytes, err := json.Marshal(resp)
	if err != nil {
		Core.Logger.Log(logger.ERROR, "failed to marshal response for caller: "+caller+", error: "+err.Error())
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(respBytes)))
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write(respBytes); err != nil {
		Core.Logger.Log(logger.ERROR, "failed to write response for caller: "+caller+", error: "+err.Error())
		return
	}

	Core.Logger.Log(logger.DEBUG, "Successfully VerifyEntity for entity: "+req.Entity.String()+" for caller: "+caller)
}
