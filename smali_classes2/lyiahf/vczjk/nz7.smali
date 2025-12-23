.class public final Llyiahf/vczjk/nz7;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field public final synthetic OooOOO:Lnow/fortuitous/thanos/sf/SFActivity;

.field public final synthetic OooOOO0:I


# direct methods
.method public synthetic constructor <init>(Lnow/fortuitous/thanos/sf/SFActivity;I)V
    .locals 0

    iput p2, p0, Llyiahf/vczjk/nz7;->OooOOO0:I

    iput-object p1, p0, Llyiahf/vczjk/nz7;->OooOOO:Lnow/fortuitous/thanos/sf/SFActivity;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 11

    iget v0, p0, Llyiahf/vczjk/nz7;->OooOOO0:I

    packed-switch v0, :pswitch_data_0

    check-cast p1, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Number;

    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    move-result p2

    and-int/lit8 p2, p2, 0x3

    const/4 v0, 0x2

    if-ne p2, v0, :cond_1

    move-object p2, p1

    check-cast p2, Llyiahf/vczjk/zf1;

    invoke-virtual {p2}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v0

    if-nez v0, :cond_0

    goto :goto_0

    :cond_0
    invoke-virtual {p2}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto :goto_1

    :cond_1
    :goto_0
    move-object v8, p1

    check-cast v8, Llyiahf/vczjk/zf1;

    const p1, 0x4c5de2

    invoke-virtual {v8, p1}, Llyiahf/vczjk/zf1;->OoooO(I)V

    iget-object p1, p0, Llyiahf/vczjk/nz7;->OooOOO:Lnow/fortuitous/thanos/sf/SFActivity;

    invoke-virtual {v8, p1}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result p2

    invoke-virtual {v8}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v0

    if-nez p2, :cond_2

    sget-object p2, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    if-ne v0, p2, :cond_3

    :cond_2
    new-instance v0, Llyiahf/vczjk/mz7;

    const/4 p2, 0x1

    invoke-direct {v0, p1, p2}, Llyiahf/vczjk/mz7;-><init>(Lnow/fortuitous/thanos/sf/SFActivity;I)V

    invoke-virtual {v8, v0}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_3
    move-object v1, v0

    check-cast v1, Llyiahf/vczjk/le3;

    const/4 p1, 0x0

    invoke-virtual {v8, p1}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    sget-object v7, Llyiahf/vczjk/yb1;->OooO00o:Llyiahf/vczjk/a91;

    const/high16 v9, 0x30000000

    const/16 v10, 0x1fe

    const/4 v2, 0x0

    const/4 v3, 0x0

    const/4 v4, 0x0

    const/4 v5, 0x0

    const/4 v6, 0x0

    invoke-static/range {v1 .. v10}, Llyiahf/vczjk/bua;->OooOO0O(Llyiahf/vczjk/le3;Llyiahf/vczjk/kl5;ZLlyiahf/vczjk/qj8;Llyiahf/vczjk/qk0;Llyiahf/vczjk/di6;Llyiahf/vczjk/bf3;Llyiahf/vczjk/rf1;II)V

    :goto_1
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :pswitch_0
    check-cast p1, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Number;

    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    move-result p2

    and-int/lit8 p2, p2, 0x3

    const/4 v0, 0x2

    if-ne p2, v0, :cond_5

    move-object p2, p1

    check-cast p2, Llyiahf/vczjk/zf1;

    invoke-virtual {p2}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v0

    if-nez v0, :cond_4

    goto :goto_2

    :cond_4
    invoke-virtual {p2}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto :goto_3

    :cond_5
    :goto_2
    iget-object p2, p0, Llyiahf/vczjk/nz7;->OooOOO:Lnow/fortuitous/thanos/sf/SFActivity;

    invoke-virtual {p2}, Landroid/app/Activity;->getIntent()Landroid/content/Intent;

    move-result-object v0

    const-string v1, "expand.search"

    const/4 v2, 0x0

    invoke-virtual {v0, v1, v2}, Landroid/content/Intent;->getBooleanExtra(Ljava/lang/String;Z)Z

    move-result v0

    check-cast p1, Llyiahf/vczjk/zf1;

    const v1, 0x4c5de2

    invoke-virtual {p1, v1}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {p1, p2}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v1

    invoke-virtual {p1}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v3

    if-nez v1, :cond_6

    sget-object v1, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    if-ne v3, v1, :cond_7

    :cond_6
    new-instance v3, Llyiahf/vczjk/mz7;

    const/4 v1, 0x0

    invoke-direct {v3, p2, v1}, Llyiahf/vczjk/mz7;-><init>(Lnow/fortuitous/thanos/sf/SFActivity;I)V

    invoke-virtual {p1, v3}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_7
    check-cast v3, Llyiahf/vczjk/le3;

    invoke-virtual {p1, v2}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-static {v0, v3, p1, v2}, Llyiahf/vczjk/kh6;->OooO0o0(ZLlyiahf/vczjk/le3;Llyiahf/vczjk/rf1;I)V

    :goto_3
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
