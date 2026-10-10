import { createClient } from '@supabase/supabase-js';

const url = process.env.NEXT_PUBLIC_SUPABASE_URL;
const secretkey =
    process.env.SUPABASE_SECRET_KEY ??
    process.env.SUPABASE_SECRET_ROLE_KEY;

if (!url) {
    console.error("Missing NEXT_PUBLIC_SUPABASE_URL in .env.local");
    process.exit(1);
}

if (!secretkey) {
    console.error(
        "Missing SUPABASE_SECRET_KEY or SUPABASE_SERVICE_ROLE_KEY in .env.local"
    );
    process.exit(1);
}

const supabase = createClient(url, secretkey, {
    auth: {
        autoRefreshToken: false,
        persistSession: false,
    },
});

const testRecord = {
    id: "day-2-connection-test",
    message: "IncidentLens Supabase connection confirmed",
};

const { error: writeError } = await supabase
    .from("setup_checks")
    .upsert(testRecord, { onConflict: "id"});

if (writeError) {
    console.error("Database write failed:", writeError.message);
    process.exit(1);
}

const { data, error: readError } = await supabase
    .from("setup_checks")
    .select("id, message")
    .eq("id", "day-2-connection-test")
    .single();

if (readError) {
    console.error("Database read failed:", readError.message);
    process.exit(1);
}

console.log("Supabase write and read both worked!");
console.log(data);