-- Run once in Supabase > SQL Editor
create table if not exists izel_records (
  c text not null, id text not null, data jsonb not null, owner text, u bigint not null,
  primary key (c, id)
);
create index if not exists izel_u on izel_records (u);
create index if not exists izel_c_owner on izel_records (c, owner);
alter table izel_records enable row level security; -- no policies: only the server (service key) can read/write
-- Storage: Supabase > Storage > New bucket named  izel-media  , keep it PRIVATE.
