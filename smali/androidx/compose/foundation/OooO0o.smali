.class public abstract Landroidx/compose/foundation/OooO0o;
.super Ljava/lang/Object;
.source "SourceFile"


# static fields
.field public static final OooO00o:Llyiahf/vczjk/l39;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    sget-object v0, Llyiahf/vczjk/zg1;->Oooo0oo:Llyiahf/vczjk/zg1;

    new-instance v1, Llyiahf/vczjk/l39;

    invoke-direct {v1, v0}, Landroidx/compose/runtime/OooO;-><init>(Llyiahf/vczjk/le3;)V

    sput-object v1, Landroidx/compose/foundation/OooO0o;->OooO00o:Llyiahf/vczjk/l39;

    return-void
.end method

.method public static final OooO00o(Llyiahf/vczjk/kl5;Llyiahf/vczjk/n24;Llyiahf/vczjk/lx3;)Llyiahf/vczjk/kl5;
    .locals 1

    if-nez p2, :cond_0

    return-object p0

    :cond_0
    instance-of v0, p2, Llyiahf/vczjk/px3;

    if-eqz v0, :cond_1

    new-instance v0, Landroidx/compose/foundation/IndicationModifierElement;

    check-cast p2, Llyiahf/vczjk/px3;

    invoke-direct {v0, p1, p2}, Landroidx/compose/foundation/IndicationModifierElement;-><init>(Llyiahf/vczjk/n24;Llyiahf/vczjk/px3;)V

    invoke-interface {p0, v0}, Llyiahf/vczjk/kl5;->OooO0oO(Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object p0

    return-object p0

    :cond_1
    new-instance v0, Llyiahf/vczjk/mx3;

    invoke-direct {v0, p2, p1}, Llyiahf/vczjk/mx3;-><init>(Llyiahf/vczjk/lx3;Llyiahf/vczjk/n24;)V

    invoke-static {p0, v0}, Llyiahf/vczjk/ng0;->OooOOoo(Llyiahf/vczjk/kl5;Llyiahf/vczjk/bf3;)Llyiahf/vczjk/kl5;

    move-result-object p0

    return-object p0
.end method
