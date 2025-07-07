CREATE OR REPLACE FUNCTION current_epoch()
RETURNS BIGINT AS $$
BEGIN
RETURN extract(epoch from now());
END;
$$ LANGUAGE plpgsql;