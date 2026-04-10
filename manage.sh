#!/bin/bash

# Honeypot Service Management Script

COMMAND=$1

print_usage() {
    echo "Usage: ./manage.sh [command]"
    echo ""
    echo "Commands:"
    echo "  start       - Start the honeypot services in the background"
    echo "  stop        - Stop and remove the honeypot containers"
    echo "  restart     - Restart the honeypot services"
    echo "  status      - Show the status of all honeypot containers"
    echo "  healthcheck - Check if the honeypot containers are running and healthy"
    echo "  logs        - View the logs of all honeypot containers"
    echo "  clean       - Stop services and remove associated volumes and networks"
    echo ""
}

case "$COMMAND" in
    start)
        echo "Starting honeypot services..."
        make run
        ;;
    stop|end)
        echo "Stopping honeypot services..."
        make stop
        ;;
    restart)
        echo "Restarting honeypot services..."
        make stop
        make run
        ;;
    status)
        echo "Honeypot services status:"
        docker compose ps
        ;;
    healthcheck)
        echo "Checking health of honeypot services..."
        docker compose ps --format "table {{.Name}}\t{{.State}}\t{{.Status}}"
        ;;
    logs)
        echo "Tailing honeypot service logs (Ctrl+C to exit)..."
        docker compose logs -f
        ;;
    clean)
        echo "Cleaning up honeypot services, volumes, and networks..."
        docker compose down -v --remove-orphans
        ;;
    *)
        print_usage
        exit 1
        ;;
esac

exit 0