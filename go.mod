module gnet

go 1.22.0

require (
	github.com/topfreegames/pitaya/v2 v2.11.9
	github.com/topfreegames/go-workers v1.2.1
)


replace (
	github.com/topfreegames/pitaya/v2 => ./gnet
	github.com/topfreegames/go-workers => ./3rd/go-workers
)
