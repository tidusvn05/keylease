package ai.keylease.designsystem

import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Shapes
import androidx.compose.ui.unit.dp

/** Spacing steps, named by their size in dp. */
object KeyleaseSpacing {
    /** Icon to badge. */
    val space2 = 2.dp
    /** Label to value inside a field. */
    val space4 = 4.dp
    /** Field row vertical padding; gap between stacked cards. */
    val space6 = 6.dp
    /** Inside a banner; between inline chips. */
    val space8 = 8.dp
    /** Between buttons in a row; banner vertical padding. */
    val space10 = 10.dp
    /** Card inner padding; gap above a card's action row. */
    val space14 = 14.dp
    /** List row and banner horizontal padding; section label inset. */
    val space16 = 16.dp
    /** Screen gutter. */
    val gutter = 18.dp
    /** Above the action stack of a state screen. */
    val space22 = 22.dp
    /** State screen horizontal padding. */
    val space28 = 28.dp
}

/** Fixed sizes. */
object KeyleaseSize {
    /** Minimum touch target for everything tappable. */
    val touchTarget = 48.dp
    /** Monogram in list rows. */
    val mark = 44.dp
    /** Monogram in a detail header. */
    val markLarge = 64.dp
    /** Icon on a state screen. */
    val stateIcon = 56.dp
    /** Width of the label column in a request summary. */
    val summaryLabel = 140.dp
}

/** Corner radii. */
object KeyleaseRadius {
    val chip = 6.dp
    val field = 8.dp
    val mark = 9.dp
    val card = 12.dp
    /** Buttons are fully rounded on their 40dp height. */
    val button = 20.dp
    val dialog = 28.dp
}

/** Material shapes mapped to the radii above. */
val KeyleaseShapes = Shapes(
    extraSmall = RoundedCornerShape(KeyleaseRadius.chip),
    small = RoundedCornerShape(KeyleaseRadius.field),
    medium = RoundedCornerShape(KeyleaseRadius.card),
    large = RoundedCornerShape(16.dp),
    extraLarge = RoundedCornerShape(KeyleaseRadius.dialog),
)
