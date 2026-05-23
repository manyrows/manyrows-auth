import { Box, Stack, Typography } from "@mui/material";
import { useTranslation } from "react-i18next";
import { useApp } from "../App.tsx";
import PageHeader from "../components/PageHeader.tsx";
import SigningKeysCard from "../profile/SigningKeysCard.tsx";

// SigningKeysPage hosts the JWT signing-key rotation panel at the
// workspace level. Super-admin only - non-super accounts see the
// "not authorised" state from SigningKeysCard itself, which keeps
// the auth check in one place.
export default function SigningKeysPage() {
  const { t } = useTranslation();
  const app = useApp();
  const isSuper = !!app.appData.account?.isSuper;

  return (
    <Box>
      <Stack spacing={3} sx={{ maxWidth: 720 }}>
        <PageHeader
          title={t("signingKeys.title")}
          subtitle={t("signingKeys.subtitle")}
          size={28}
          mb={0}
        />

        {!isSuper ? (
          <Typography variant="body2" color="text.secondary">
            {t("signingKeys.superOnly")}
          </Typography>
        ) : (
          <SigningKeysCard isSuper={isSuper} />
        )}
      </Stack>
    </Box>
  );
}
