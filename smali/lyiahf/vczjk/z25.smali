.class public final Llyiahf/vczjk/z25;
.super Ljava/lang/Object;
.source "SourceFile"


# static fields
.field public static final OooO:Llyiahf/vczjk/cs0;

.field public static final OooOO0:Llyiahf/vczjk/j92;


# instance fields
.field public OooO00o:I

.field public OooO0O0:F

.field public OooO0OO:F

.field public OooO0Oo:Landroid/animation/ObjectAnimator;

.field public OooO0o:Lcom/google/android/material/loadingindicator/LoadingIndicatorSpec;

.field public OooO0o0:Llyiahf/vczjk/rz8;

.field public OooO0oO:Llyiahf/vczjk/b35;

.field public OooO0oo:Llyiahf/vczjk/c35;


# direct methods
.method static constructor <clinit>()V
    .locals 4

    new-instance v0, Llyiahf/vczjk/cs0;

    const-class v1, Ljava/lang/Float;

    const-string v2, "animationFraction"

    const/16 v3, 0x13

    invoke-direct {v0, v1, v2, v3}, Llyiahf/vczjk/cs0;-><init>(Ljava/lang/Class;Ljava/lang/String;I)V

    sput-object v0, Llyiahf/vczjk/z25;->OooO:Llyiahf/vczjk/cs0;

    new-instance v0, Llyiahf/vczjk/j92;

    const/4 v1, 0x1

    invoke-direct {v0, v1}, Llyiahf/vczjk/j92;-><init>(I)V

    sput-object v0, Llyiahf/vczjk/z25;->OooOO0:Llyiahf/vczjk/j92;

    return-void
.end method


# virtual methods
.method public final OooO00o(F)V
    .locals 6

    iput p1, p0, Llyiahf/vczjk/z25;->OooO0OO:F

    iget-object v0, p0, Llyiahf/vczjk/z25;->OooO0oo:Llyiahf/vczjk/c35;

    iput p1, v0, Llyiahf/vczjk/c35;->OooO0O0:F

    iget v1, p0, Llyiahf/vczjk/z25;->OooO00o:I

    add-int/lit8 v1, v1, -0x1

    iget-object v2, p0, Llyiahf/vczjk/z25;->OooO0o:Lcom/google/android/material/loadingindicator/LoadingIndicatorSpec;

    iget-object v2, v2, Lcom/google/android/material/loadingindicator/LoadingIndicatorSpec;->OooO0Oo:[I

    array-length v3, v2

    rem-int v3, v1, v3

    add-int/lit8 v4, v3, 0x1

    array-length v5, v2

    rem-int/2addr v4, v5

    aget v3, v2, v3

    aget v2, v2, v4

    int-to-float v1, v1

    sub-float/2addr p1, v1

    const/4 v1, 0x0

    const/high16 v4, 0x3f800000    # 1.0f

    invoke-static {p1, v1, v4}, Llyiahf/vczjk/l4a;->OooOOO(FFF)F

    move-result p1

    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v1

    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v2

    invoke-static {p1, v1, v2}, Llyiahf/vczjk/kx;->OooO00o(FLjava/lang/Integer;Ljava/lang/Integer;)Ljava/lang/Integer;

    move-result-object p1

    invoke-virtual {p1}, Ljava/lang/Integer;->intValue()I

    move-result p1

    iput p1, v0, Llyiahf/vczjk/c35;->OooO00o:I

    iget-object p1, p0, Llyiahf/vczjk/z25;->OooO0oO:Llyiahf/vczjk/b35;

    if-eqz p1, :cond_0

    invoke-virtual {p1}, Landroid/graphics/drawable/Drawable;->invalidateSelf()V

    :cond_0
    return-void
.end method
