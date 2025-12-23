.class public final synthetic Llyiahf/vczjk/ve5;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field public final synthetic OooOOO:Llyiahf/vczjk/cf3;

.field public final synthetic OooOOO0:I

.field public final synthetic OooOOOO:I

.field public final synthetic OooOOOo:Ljava/lang/Object;

.field public final synthetic OooOOo:Ljava/lang/Object;

.field public final synthetic OooOOo0:Ljava/lang/Object;

.field public final synthetic OooOOoo:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Llyiahf/vczjk/cf3;II)V
    .locals 0

    iput p7, p0, Llyiahf/vczjk/ve5;->OooOOO0:I

    iput-object p1, p0, Llyiahf/vczjk/ve5;->OooOOOo:Ljava/lang/Object;

    iput-object p2, p0, Llyiahf/vczjk/ve5;->OooOOo0:Ljava/lang/Object;

    iput-object p3, p0, Llyiahf/vczjk/ve5;->OooOOo:Ljava/lang/Object;

    iput-object p4, p0, Llyiahf/vczjk/ve5;->OooOOoo:Ljava/lang/Object;

    iput-object p5, p0, Llyiahf/vczjk/ve5;->OooOOO:Llyiahf/vczjk/cf3;

    iput p6, p0, Llyiahf/vczjk/ve5;->OooOOOO:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 8

    iget v0, p0, Llyiahf/vczjk/ve5;->OooOOO0:I

    packed-switch v0, :pswitch_data_0

    move-object v6, p1

    check-cast v6, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Integer;

    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    iget p1, p0, Llyiahf/vczjk/ve5;->OooOOOO:I

    or-int/lit8 p1, p1, 0x1

    invoke-static {p1}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result v7

    iget-object p1, p0, Llyiahf/vczjk/ve5;->OooOOOo:Ljava/lang/Object;

    move-object v1, p1

    check-cast v1, Llyiahf/vczjk/bi6;

    iget-object p1, p0, Llyiahf/vczjk/ve5;->OooOOo0:Ljava/lang/Object;

    move-object v2, p1

    check-cast v2, Llyiahf/vczjk/j19;

    iget-object p1, p0, Llyiahf/vczjk/ve5;->OooOOo:Ljava/lang/Object;

    move-object v3, p1

    check-cast v3, Llyiahf/vczjk/oe3;

    iget-object p1, p0, Llyiahf/vczjk/ve5;->OooOOoo:Ljava/lang/Object;

    move-object v4, p1

    check-cast v4, Llyiahf/vczjk/oe3;

    iget-object p1, p0, Llyiahf/vczjk/ve5;->OooOOO:Llyiahf/vczjk/cf3;

    move-object v5, p1

    check-cast v5, Llyiahf/vczjk/le3;

    invoke-static/range {v1 .. v7}, Llyiahf/vczjk/er8;->OooO0oo(Llyiahf/vczjk/bi6;Llyiahf/vczjk/j19;Llyiahf/vczjk/oe3;Llyiahf/vczjk/oe3;Llyiahf/vczjk/le3;Llyiahf/vczjk/rf1;I)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :pswitch_0
    move-object v5, p1

    check-cast v5, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Integer;

    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    iget p1, p0, Llyiahf/vczjk/ve5;->OooOOOO:I

    or-int/lit8 p1, p1, 0x1

    invoke-static {p1}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result v6

    iget-object p1, p0, Llyiahf/vczjk/ve5;->OooOOo:Ljava/lang/Object;

    move-object v2, p1

    check-cast v2, Llyiahf/vczjk/kl5;

    iget-object p1, p0, Llyiahf/vczjk/ve5;->OooOOoo:Ljava/lang/Object;

    move-object v3, p1

    check-cast v3, Llyiahf/vczjk/kl5;

    iget-object p1, p0, Llyiahf/vczjk/ve5;->OooOOO:Llyiahf/vczjk/cf3;

    move-object v4, p1

    check-cast v4, Llyiahf/vczjk/a91;

    iget-object p1, p0, Llyiahf/vczjk/ve5;->OooOOOo:Ljava/lang/Object;

    move-object v0, p1

    check-cast v0, Llyiahf/vczjk/fq7;

    iget-object p1, p0, Llyiahf/vczjk/ve5;->OooOOo0:Ljava/lang/Object;

    move-object v1, p1

    check-cast v1, Lgithub/tornaco/android/thanos/module/compose/common/widget/SortItem;

    invoke-static/range {v0 .. v6}, Llyiahf/vczjk/fu6;->OooO0o0(Llyiahf/vczjk/fq7;Lgithub/tornaco/android/thanos/module/compose/common/widget/SortItem;Llyiahf/vczjk/kl5;Llyiahf/vczjk/kl5;Llyiahf/vczjk/a91;Llyiahf/vczjk/rf1;I)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :pswitch_1
    move-object v5, p1

    check-cast v5, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Integer;

    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    iget p1, p0, Llyiahf/vczjk/ve5;->OooOOOO:I

    or-int/lit8 p1, p1, 0x1

    invoke-static {p1}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result v6

    iget-object p1, p0, Llyiahf/vczjk/ve5;->OooOOO:Llyiahf/vczjk/cf3;

    move-object v4, p1

    check-cast v4, Llyiahf/vczjk/a91;

    iget-object p1, p0, Llyiahf/vczjk/ve5;->OooOOOo:Ljava/lang/Object;

    move-object v0, p1

    check-cast v0, Llyiahf/vczjk/x21;

    iget-object p1, p0, Llyiahf/vczjk/ve5;->OooOOo0:Ljava/lang/Object;

    move-object v1, p1

    check-cast v1, Llyiahf/vczjk/yo5;

    iget-object p1, p0, Llyiahf/vczjk/ve5;->OooOOo:Ljava/lang/Object;

    move-object v2, p1

    check-cast v2, Llyiahf/vczjk/al8;

    iget-object p1, p0, Llyiahf/vczjk/ve5;->OooOOoo:Ljava/lang/Object;

    move-object v3, p1

    check-cast v3, Llyiahf/vczjk/n6a;

    invoke-static/range {v0 .. v6}, Llyiahf/vczjk/we5;->OooO0O0(Llyiahf/vczjk/x21;Llyiahf/vczjk/yo5;Llyiahf/vczjk/al8;Llyiahf/vczjk/n6a;Llyiahf/vczjk/a91;Llyiahf/vczjk/rf1;I)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
