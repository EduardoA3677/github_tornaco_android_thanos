.class public final synthetic Llyiahf/vczjk/ga;
.super Llyiahf/vczjk/hs5;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ig4;


# instance fields
.field public final synthetic OooOOO:I


# direct methods
.method public synthetic constructor <init>(IILjava/lang/Class;Ljava/lang/Object;Ljava/lang/String;Ljava/lang/String;)V
    .locals 0

    iput p2, p0, Llyiahf/vczjk/ga;->OooOOO:I

    move-object p2, p4

    move-object p4, p5

    move-object p5, p6

    move p6, p1

    move-object p1, p0

    invoke-direct/range {p1 .. p6}, Llyiahf/vczjk/ab7;-><init>(Ljava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;I)V

    return-void
.end method


# virtual methods
.method public final OooO00o()Ljava/lang/Object;
    .locals 1

    invoke-interface {p0}, Llyiahf/vczjk/hh4;->get()Ljava/lang/Object;

    move-result-object v0

    return-object v0
.end method

.method public final bridge synthetic OooO0O0()Llyiahf/vczjk/fh4;
    .locals 1

    invoke-virtual {p0}, Llyiahf/vczjk/ga;->OooO0O0()Llyiahf/vczjk/gh4;

    move-result-object v0

    return-object v0
.end method

.method public final OooO0O0()Llyiahf/vczjk/gh4;
    .locals 1

    invoke-virtual {p0}, Llyiahf/vczjk/ab7;->OooOOO()Llyiahf/vczjk/th4;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/ig4;

    invoke-interface {v0}, Llyiahf/vczjk/hh4;->OooO0O0()Llyiahf/vczjk/gh4;

    move-result-object v0

    return-object v0
.end method

.method public final bridge synthetic OooO0OO()Llyiahf/vczjk/gg4;
    .locals 1

    invoke-virtual {p0}, Llyiahf/vczjk/ga;->OooO0OO()Llyiahf/vczjk/hg4;

    move-result-object v0

    return-object v0
.end method

.method public final OooO0OO()Llyiahf/vczjk/hg4;
    .locals 1

    invoke-virtual {p0}, Llyiahf/vczjk/ab7;->OooOOO()Llyiahf/vczjk/th4;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/ig4;

    invoke-interface {v0}, Llyiahf/vczjk/ig4;->OooO0OO()Llyiahf/vczjk/hg4;

    move-result-object v0

    return-object v0
.end method

.method public final OooO0oO()Llyiahf/vczjk/bf4;
    .locals 1

    sget-object v0, Llyiahf/vczjk/ym7;->OooO00o:Llyiahf/vczjk/zm7;

    invoke-virtual {v0, p0}, Llyiahf/vczjk/zm7;->OooO0Oo(Llyiahf/vczjk/ga;)Llyiahf/vczjk/ig4;

    move-result-object v0

    return-object v0
.end method

.method public final get()Ljava/lang/Object;
    .locals 1

    iget v0, p0, Llyiahf/vczjk/ga;->OooOOO:I

    packed-switch v0, :pswitch_data_0

    iget-object v0, p0, Llyiahf/vczjk/go0;->receiver:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/qs5;

    invoke-interface {v0}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v0

    return-object v0

    :pswitch_0
    iget-object v0, p0, Llyiahf/vczjk/go0;->receiver:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/r83;

    iget-object v0, v0, Llyiahf/vczjk/r83;->OooOO0o:Llyiahf/vczjk/d93;

    return-object v0

    :pswitch_1
    iget-object v0, p0, Llyiahf/vczjk/go0;->receiver:Ljava/lang/Object;

    check-cast v0, Landroidx/compose/ui/tooling/ComposeViewAdapter;

    invoke-virtual {v0}, Landroidx/compose/ui/tooling/ComposeViewAdapter;->getClock$ui_tooling_release()Llyiahf/vczjk/e47;

    move-result-object v0

    return-object v0

    :pswitch_2
    iget-object v0, p0, Llyiahf/vczjk/go0;->receiver:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/xa;

    invoke-virtual {v0}, Llyiahf/vczjk/xa;->getLayoutDirection()Llyiahf/vczjk/yn4;

    move-result-object v0

    return-object v0

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
