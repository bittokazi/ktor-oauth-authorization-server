CREATE OR REPLACE FUNCTION prevent_default_client_delete()
RETURNS TRIGGER AS $$
BEGIN
    IF OLD.is_default THEN
        RAISE EXCEPTION 'Cannot delete default OAuth client.';
    END IF;
    RETURN OLD;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_prevent_default_client_delete
BEFORE DELETE ON oauth_clients
FOR EACH ROW
EXECUTE FUNCTION prevent_default_client_delete();
