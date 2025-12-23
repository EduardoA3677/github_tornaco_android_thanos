.class public final synthetic Llyiahf/vczjk/qd;
.super Llyiahf/vczjk/wf3;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic $node:Llyiahf/vczjk/ex4;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/ex4;)V
    .locals 6

    iput-object p1, p0, Llyiahf/vczjk/qd;->$node:Llyiahf/vczjk/ex4;

    const-class v2, Llyiahf/vczjk/u34;

    const-string v3, "localToScreen"

    const/4 v1, 0x1

    const-string v4, "startInput$localToScreen(Landroidx/compose/foundation/text/input/internal/LegacyPlatformTextInputServiceAdapter$LegacyPlatformTextInputNode;[F)V"

    const/4 v5, 0x0

    move-object v0, p0

    invoke-direct/range {v0 .. v5}, Llyiahf/vczjk/wf3;-><init>(ILjava/lang/Class;Ljava/lang/String;Ljava/lang/String;I)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    check-cast p1, Llyiahf/vczjk/ze5;

    iget-object p1, p1, Llyiahf/vczjk/ze5;->OooO00o:[F

    iget-object v0, p0, Llyiahf/vczjk/qd;->$node:Llyiahf/vczjk/ex4;

    check-cast v0, Llyiahf/vczjk/cx4;

    iget-object v0, v0, Llyiahf/vczjk/cx4;->OooOooO:Llyiahf/vczjk/qs5;

    check-cast v0, Llyiahf/vczjk/fw8;

    invoke-virtual {v0}, Llyiahf/vczjk/fw8;->getValue()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/xn4;

    if-eqz v0, :cond_2

    invoke-interface {v0}, Llyiahf/vczjk/xn4;->OooOO0o()Z

    move-result v1

    if-eqz v1, :cond_0

    goto :goto_0

    :cond_0
    const/4 v0, 0x0

    :goto_0
    if-nez v0, :cond_1

    goto :goto_1

    :cond_1
    invoke-interface {v0, p1}, Llyiahf/vczjk/xn4;->OooOOo([F)V

    :cond_2
    :goto_1
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
