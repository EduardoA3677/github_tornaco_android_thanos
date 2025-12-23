.class public final Llyiahf/vczjk/qo7;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic $this_with:Llyiahf/vczjk/k68;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/k68;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>(Llyiahf/vczjk/era;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/qo7;->$this_with:Llyiahf/vczjk/k68;

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    check-cast p1, Llyiahf/vczjk/qs5;

    instance-of v0, p1, Llyiahf/vczjk/dw8;

    if-eqz v0, :cond_1

    invoke-interface {p1}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v0

    if-eqz v0, :cond_0

    iget-object v0, p0, Llyiahf/vczjk/qo7;->$this_with:Llyiahf/vczjk/k68;

    invoke-interface {p1}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v1

    invoke-static {v1}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    invoke-interface {v0, v1}, Llyiahf/vczjk/k68;->OooO0oo(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v0

    goto :goto_0

    :cond_0
    const/4 v0, 0x0

    :goto_0
    check-cast p1, Llyiahf/vczjk/dw8;

    invoke-interface {p1}, Llyiahf/vczjk/dw8;->OooO0o()Llyiahf/vczjk/gw8;

    move-result-object p1

    const-string v1, "null cannot be cast to non-null type androidx.compose.runtime.SnapshotMutationPolicy<T of androidx.compose.runtime.saveable.RememberSaveableKt.mutableStateSaver?>"

    invoke-static {p1, v1}, Llyiahf/vczjk/v34;->OooOo(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {v0, p1}, Landroidx/compose/runtime/OooO0o;->OooO(Ljava/lang/Object;Llyiahf/vczjk/gw8;)Llyiahf/vczjk/qs5;

    move-result-object p1

    return-object p1

    :cond_1
    new-instance p1, Ljava/lang/IllegalArgumentException;

    const-string v0, "Failed requirement."

    invoke-direct {p1, v0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p1
.end method
