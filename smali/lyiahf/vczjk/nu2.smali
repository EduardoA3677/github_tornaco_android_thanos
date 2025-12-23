.class public final synthetic Llyiahf/vczjk/nu2;
.super Llyiahf/vczjk/wf3;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    check-cast p1, Landroidx/window/extensions/layout/WindowLayoutInfo;

    const-string v0, "p0"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v0, p0, Llyiahf/vczjk/go0;->receiver:Ljava/lang/Object;

    check-cast v0, Landroidx/window/layout/adapter/extensions/MulticastConsumer;

    invoke-virtual {v0, p1}, Landroidx/window/layout/adapter/extensions/MulticastConsumer;->accept(Landroidx/window/extensions/layout/WindowLayoutInfo;)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
