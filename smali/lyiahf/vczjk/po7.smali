.class public final Llyiahf/vczjk/po7;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


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

    iput-object p1, p0, Llyiahf/vczjk/po7;->$this_with:Llyiahf/vczjk/k68;

    const/4 p1, 0x2

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    check-cast p1, Llyiahf/vczjk/n58;

    check-cast p2, Llyiahf/vczjk/qs5;

    instance-of v0, p2, Llyiahf/vczjk/dw8;

    if-eqz v0, :cond_1

    iget-object v0, p0, Llyiahf/vczjk/po7;->$this_with:Llyiahf/vczjk/k68;

    invoke-interface {p2}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v1

    invoke-interface {v0, p1, v1}, Llyiahf/vczjk/k68;->OooO00o(Llyiahf/vczjk/n58;Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    if-eqz p1, :cond_0

    check-cast p2, Llyiahf/vczjk/dw8;

    invoke-interface {p2}, Llyiahf/vczjk/dw8;->OooO0o()Llyiahf/vczjk/gw8;

    move-result-object p2

    const-string v0, "null cannot be cast to non-null type androidx.compose.runtime.SnapshotMutationPolicy<kotlin.Any?>"

    invoke-static {p2, v0}, Llyiahf/vczjk/v34;->OooOo(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {p1, p2}, Landroidx/compose/runtime/OooO0o;->OooO(Ljava/lang/Object;Llyiahf/vczjk/gw8;)Llyiahf/vczjk/qs5;

    move-result-object p1

    return-object p1

    :cond_0
    const/4 p1, 0x0

    return-object p1

    :cond_1
    new-instance p1, Ljava/lang/IllegalArgumentException;

    const-string p2, "If you use a custom MutableState implementation you have to write a custom Saver and pass it as a saver param to rememberSaveable()"

    invoke-direct {p1, p2}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p1
.end method
