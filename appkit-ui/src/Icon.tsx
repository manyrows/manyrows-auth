import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import {
  faXmark,
  faRightFromBracket,
  faPen,
  faCheck,
  faShieldHalved,
  faCode,
  faLock,
  faEye,
  faEyeSlash,
  faSpinner,
  faFingerprint,
  faKey,
  faTrash,
  faQrcode,
} from "@fortawesome/free-solid-svg-icons";
import {
  faCircleCheck,
  faEnvelope,
} from "@fortawesome/free-regular-svg-icons";
import type { IconDefinition } from "@fortawesome/fontawesome-svg-core";

const icons: Record<string, IconDefinition> = {
  xmark: faXmark,
  close: faXmark,
  logout: faRightFromBracket,
  edit: faPen,
  check: faCheck,
  shield: faShieldHalved,
  "circle-check": faCircleCheck,
  code: faCode,
  envelope: faEnvelope,
  lock: faLock,
  eye: faEye,
  "eye-slash": faEyeSlash,
  spinner: faSpinner,
  fingerprint: faFingerprint,
  key: faKey,
  trash: faTrash,
  qrcode: faQrcode,
};

export default function Icon({
  name,
  size,
  className,
  style,
}: {
  name: string;
  size?: number;
  className?: string;
  style?: React.CSSProperties;
}) {
  const icon = icons[name];
  if (!icon) return null;
  return (
    <FontAwesomeIcon
      icon={icon}
      style={{ fontSize: size, ...style }}
      className={className}
      spin={name === "spinner"}
    />
  );
}
