.class public final Llyiahf/vczjk/w73;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/iw7;


# static fields
.field public static final OooO00o:Llyiahf/vczjk/w73;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    new-instance v0, Llyiahf/vczjk/w73;

    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    sput-object v0, Llyiahf/vczjk/w73;->OooO00o:Llyiahf/vczjk/w73;

    return-void
.end method


# virtual methods
.method public final OooO00o(Llyiahf/vczjk/kl5;Z)Llyiahf/vczjk/kl5;
    .locals 4

    const/high16 p2, 0x3f800000    # 1.0f

    float-to-double v0, p2

    const-wide/16 v2, 0x0

    cmpl-double v0, v0, v2

    if-lez v0, :cond_0

    goto :goto_0

    :cond_0
    const-string v0, "invalid weight; must be greater than zero"

    invoke-static {v0}, Llyiahf/vczjk/nz3;->OooO00o(Ljava/lang/String;)V

    :goto_0
    new-instance v0, Landroidx/compose/foundation/layout/LayoutWeightElement;

    const/4 v1, 0x1

    invoke-direct {v0, p2, v1}, Landroidx/compose/foundation/layout/LayoutWeightElement;-><init>(FZ)V

    invoke-interface {p1, v0}, Llyiahf/vczjk/kl5;->OooO0oO(Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object p1

    return-object p1
.end method
