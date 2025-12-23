.class public abstract Llyiahf/vczjk/gb9;
.super Ljava/lang/Object;
.source "SourceFile"


# static fields
.field public static final OooO00o:Llyiahf/vczjk/ey6;


# direct methods
.method static constructor <clinit>()V
    .locals 3

    new-instance v0, Llyiahf/vczjk/ey6;

    sget-object v1, Llyiahf/vczjk/an2;->OooOOO0:Llyiahf/vczjk/an2;

    const/4 v2, 0x0

    invoke-direct {v0, v1, v2}, Llyiahf/vczjk/ey6;-><init>(Ljava/util/List;Llyiahf/vczjk/hl1;)V

    sput-object v0, Llyiahf/vczjk/gb9;->OooO00o:Llyiahf/vczjk/ey6;

    return-void
.end method

.method public static final OooO00o(Llyiahf/vczjk/kl5;Ljava/lang/Object;Landroidx/compose/ui/input/pointer/PointerInputEventHandler;)Llyiahf/vczjk/kl5;
    .locals 3

    new-instance v0, Landroidx/compose/ui/input/pointer/SuspendPointerInputElement;

    const/4 v1, 0x6

    const/4 v2, 0x0

    invoke-direct {v0, p1, v2, p2, v1}, Landroidx/compose/ui/input/pointer/SuspendPointerInputElement;-><init>(Ljava/lang/Object;Ljava/lang/Object;Landroidx/compose/ui/input/pointer/PointerInputEventHandler;I)V

    invoke-interface {p0, v0}, Llyiahf/vczjk/kl5;->OooO0oO(Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object p0

    return-object p0
.end method
