.class public final Llyiahf/vczjk/xo5;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/yo5;


# static fields
.field public static final OooO00o:Llyiahf/vczjk/xo5;

.field public static final OooO0O0:Llyiahf/vczjk/wz8;

.field public static final OooO0OO:Llyiahf/vczjk/wz8;

.field public static final OooO0Oo:Llyiahf/vczjk/wz8;

.field public static final OooO0o:Llyiahf/vczjk/wz8;

.field public static final OooO0o0:Llyiahf/vczjk/wz8;

.field public static final OooO0oO:Llyiahf/vczjk/wz8;


# direct methods
.method static constructor <clinit>()V
    .locals 4

    new-instance v0, Llyiahf/vczjk/xo5;

    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    sput-object v0, Llyiahf/vczjk/xo5;->OooO00o:Llyiahf/vczjk/xo5;

    const v0, 0x3f666666    # 0.9f

    const/high16 v1, 0x442f0000    # 700.0f

    const/4 v2, 0x0

    const/4 v3, 0x4

    invoke-static {v0, v1, v2, v3}, Llyiahf/vczjk/ng0;->OoooOoo(FFLjava/lang/Object;I)Llyiahf/vczjk/wz8;

    move-result-object v1

    sput-object v1, Llyiahf/vczjk/xo5;->OooO0O0:Llyiahf/vczjk/wz8;

    const/high16 v1, 0x44af0000    # 1400.0f

    invoke-static {v0, v1, v2, v3}, Llyiahf/vczjk/ng0;->OoooOoo(FFLjava/lang/Object;I)Llyiahf/vczjk/wz8;

    move-result-object v1

    sput-object v1, Llyiahf/vczjk/xo5;->OooO0OO:Llyiahf/vczjk/wz8;

    const/high16 v1, 0x43960000    # 300.0f

    invoke-static {v0, v1, v2, v3}, Llyiahf/vczjk/ng0;->OoooOoo(FFLjava/lang/Object;I)Llyiahf/vczjk/wz8;

    move-result-object v0

    sput-object v0, Llyiahf/vczjk/xo5;->OooO0Oo:Llyiahf/vczjk/wz8;

    const/high16 v0, 0x3f800000    # 1.0f

    const/high16 v1, 0x44c80000    # 1600.0f

    invoke-static {v0, v1, v2, v3}, Llyiahf/vczjk/ng0;->OoooOoo(FFLjava/lang/Object;I)Llyiahf/vczjk/wz8;

    move-result-object v1

    sput-object v1, Llyiahf/vczjk/xo5;->OooO0o0:Llyiahf/vczjk/wz8;

    const v1, 0x456d8000    # 3800.0f

    invoke-static {v0, v1, v2, v3}, Llyiahf/vczjk/ng0;->OoooOoo(FFLjava/lang/Object;I)Llyiahf/vczjk/wz8;

    move-result-object v1

    sput-object v1, Llyiahf/vczjk/xo5;->OooO0o:Llyiahf/vczjk/wz8;

    const/high16 v1, 0x44480000    # 800.0f

    invoke-static {v0, v1, v2, v3}, Llyiahf/vczjk/ng0;->OoooOoo(FFLjava/lang/Object;I)Llyiahf/vczjk/wz8;

    move-result-object v0

    sput-object v0, Llyiahf/vczjk/xo5;->OooO0oO:Llyiahf/vczjk/wz8;

    return-void
.end method


# virtual methods
.method public final OooO00o()Llyiahf/vczjk/wz8;
    .locals 2

    sget-object v0, Llyiahf/vczjk/xo5;->OooO0oO:Llyiahf/vczjk/wz8;

    const-string v1, "null cannot be cast to non-null type androidx.compose.animation.core.FiniteAnimationSpec<T of androidx.compose.material3.MotionScheme.StandardMotionSchemeImpl.slowEffectsSpec>"

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOo(Ljava/lang/Object;Ljava/lang/String;)V

    return-object v0
.end method

.method public final OooO0O0()Llyiahf/vczjk/wz8;
    .locals 2

    sget-object v0, Llyiahf/vczjk/xo5;->OooO0o:Llyiahf/vczjk/wz8;

    const-string v1, "null cannot be cast to non-null type androidx.compose.animation.core.FiniteAnimationSpec<T of androidx.compose.material3.MotionScheme.StandardMotionSchemeImpl.fastEffectsSpec>"

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOo(Ljava/lang/Object;Ljava/lang/String;)V

    return-object v0
.end method

.method public final OooO0OO()Llyiahf/vczjk/wz8;
    .locals 2

    sget-object v0, Llyiahf/vczjk/xo5;->OooO0OO:Llyiahf/vczjk/wz8;

    const-string v1, "null cannot be cast to non-null type androidx.compose.animation.core.FiniteAnimationSpec<T of androidx.compose.material3.MotionScheme.StandardMotionSchemeImpl.fastSpatialSpec>"

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOo(Ljava/lang/Object;Ljava/lang/String;)V

    return-object v0
.end method

.method public final OooO0Oo()Llyiahf/vczjk/wz8;
    .locals 2

    sget-object v0, Llyiahf/vczjk/xo5;->OooO0o0:Llyiahf/vczjk/wz8;

    const-string v1, "null cannot be cast to non-null type androidx.compose.animation.core.FiniteAnimationSpec<T of androidx.compose.material3.MotionScheme.StandardMotionSchemeImpl.defaultEffectsSpec>"

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOo(Ljava/lang/Object;Ljava/lang/String;)V

    return-object v0
.end method

.method public final OooO0o()Llyiahf/vczjk/wz8;
    .locals 2

    sget-object v0, Llyiahf/vczjk/xo5;->OooO0O0:Llyiahf/vczjk/wz8;

    const-string v1, "null cannot be cast to non-null type androidx.compose.animation.core.FiniteAnimationSpec<T of androidx.compose.material3.MotionScheme.StandardMotionSchemeImpl.defaultSpatialSpec>"

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOo(Ljava/lang/Object;Ljava/lang/String;)V

    return-object v0
.end method

.method public final OooO0o0()Llyiahf/vczjk/wz8;
    .locals 2

    sget-object v0, Llyiahf/vczjk/xo5;->OooO0Oo:Llyiahf/vczjk/wz8;

    const-string v1, "null cannot be cast to non-null type androidx.compose.animation.core.FiniteAnimationSpec<T of androidx.compose.material3.MotionScheme.StandardMotionSchemeImpl.slowSpatialSpec>"

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOo(Ljava/lang/Object;Ljava/lang/String;)V

    return-object v0
.end method
