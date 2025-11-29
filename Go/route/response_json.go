/*
 * Auth: response_json.go
 * Copyright (C) 2025 mtctx
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the **GNU General Public License** as published
 * by the Free Software Foundation, either **version 3** of the License, or
 * (at your option) any later version.
 *
 * *This program is distributed WITHOUT ANY WARRANTY;** see the
 * GNU General Public License for more details, which you should have
 * received with this program.
 *
 * SPDX-FileCopyrightText: 2025 mtctx
 * SPDX-License-Identifier: GPL-3.0-only
 */

package route

import (
	"net/http"

	"github.com/rs/zerolog"
)

func Respond(writer http.ResponseWriter) *zerolog.Event {
	writer.Header().Set("Content-Type", "application/json")
	logger := zerolog.New(writer).Level(zerolog.Disabled).With().Timestamp().Logger()
	return logger.Log()
}
