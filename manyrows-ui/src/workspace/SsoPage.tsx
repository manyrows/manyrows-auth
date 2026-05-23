import { Box, Stack, Typography } from "@mui/material";
import { Fingerprint } from "lucide-react";
import { useTranslation } from "react-i18next";
import PageHeader from "../components/PageHeader.tsx";
import EmptyState from "../components/EmptyState.tsx";
import StatusChip from "../components/StatusChip.tsx";

export default function SsoPage() {
  const { t } = useTranslation();
  return (
    <Box>
      <PageHeader
        title="SSO"
        subtitle={t("sso.subtitle")}
        meta={<StatusChip label={t("sso.comingSoon")} severity="primary" />}
      />

      <EmptyState
        icon={<Fingerprint size={20} strokeWidth={1.5} />}
        title={t("sso.empty.title")}
        description={
          <Stack spacing={1} alignItems="center">
            <Typography variant="body2" color="text.secondary">
              {t("sso.empty.description")}
            </Typography>
          </Stack>
        }
        maxWidth={520}
      />
    </Box>
  );
}