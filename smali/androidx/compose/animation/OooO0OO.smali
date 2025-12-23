.class public abstract Landroidx/compose/animation/OooO0OO;
.super Ljava/lang/Object;
.source "SourceFile"


# static fields
.field public static final OooO00o:J


# direct methods
.method static constructor <clinit>()V
    .locals 6

    const/high16 v0, -0x80000000

    int-to-long v0, v0

    const/16 v2, 0x20

    shl-long v2, v0, v2

    const-wide v4, 0xffffffffL

    and-long/2addr v0, v4

    or-long/2addr v0, v2

    sput-wide v0, Landroidx/compose/animation/OooO0OO;->OooO00o:J

    return-void
.end method

.method public static OooO00o(Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;
    .locals 7

    const/4 v0, 0x1

    int-to-long v1, v0

    const/16 v3, 0x20

    shl-long v3, v1, v3

    const-wide v5, 0xffffffffL

    and-long/2addr v1, v5

    or-long/2addr v1, v3

    new-instance v3, Llyiahf/vczjk/b24;

    invoke-direct {v3, v1, v2}, Llyiahf/vczjk/b24;-><init>(J)V

    const/4 v1, 0x0

    const/high16 v2, 0x43c80000    # 400.0f

    invoke-static {v1, v2, v3, v0}, Llyiahf/vczjk/ng0;->OoooOoo(FFLjava/lang/Object;I)Llyiahf/vczjk/wz8;

    move-result-object v0

    invoke-static {p0}, Llyiahf/vczjk/zsa;->Oooo000(Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object p0

    new-instance v1, Landroidx/compose/animation/SizeAnimationModifierElement;

    invoke-direct {v1, v0}, Landroidx/compose/animation/SizeAnimationModifierElement;-><init>(Llyiahf/vczjk/wz8;)V

    invoke-interface {p0, v1}, Llyiahf/vczjk/kl5;->OooO0oO(Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object p0

    return-object p0
.end method
