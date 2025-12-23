.class public final synthetic Llyiahf/vczjk/gv0;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field public final synthetic OooOOO:Z

.field public final synthetic OooOOO0:I

.field public final synthetic OooOOOO:I

.field public final synthetic OooOOOo:Ljava/lang/Object;

.field public final synthetic OooOOo:Ljava/lang/Object;

.field public final synthetic OooOOo0:Ljava/lang/Object;

.field public final synthetic OooOOoo:Ljava/lang/Object;

.field public final synthetic OooOo0:Ljava/lang/Object;

.field public final synthetic OooOo00:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/cs8;Llyiahf/vczjk/hl5;ZLlyiahf/vczjk/ir8;Llyiahf/vczjk/rr5;Llyiahf/vczjk/a91;Llyiahf/vczjk/a91;I)V
    .locals 1

    const/4 v0, 0x1

    iput v0, p0, Llyiahf/vczjk/gv0;->OooOOO0:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/gv0;->OooOOOo:Ljava/lang/Object;

    iput-object p2, p0, Llyiahf/vczjk/gv0;->OooOOo0:Ljava/lang/Object;

    iput-boolean p3, p0, Llyiahf/vczjk/gv0;->OooOOO:Z

    iput-object p4, p0, Llyiahf/vczjk/gv0;->OooOOo:Ljava/lang/Object;

    iput-object p5, p0, Llyiahf/vczjk/gv0;->OooOOoo:Ljava/lang/Object;

    iput-object p6, p0, Llyiahf/vczjk/gv0;->OooOo00:Ljava/lang/Object;

    iput-object p7, p0, Llyiahf/vczjk/gv0;->OooOo0:Ljava/lang/Object;

    iput p8, p0, Llyiahf/vczjk/gv0;->OooOOOO:I

    return-void
.end method

.method public synthetic constructor <init>(Llyiahf/vczjk/gt9;Llyiahf/vczjk/le3;Llyiahf/vczjk/h79;Llyiahf/vczjk/h79;Llyiahf/vczjk/kl5;ZLlyiahf/vczjk/cv0;I)V
    .locals 1

    const/4 v0, 0x0

    iput v0, p0, Llyiahf/vczjk/gv0;->OooOOO0:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/gv0;->OooOOOo:Ljava/lang/Object;

    iput-object p2, p0, Llyiahf/vczjk/gv0;->OooOOo0:Ljava/lang/Object;

    iput-object p3, p0, Llyiahf/vczjk/gv0;->OooOOo:Ljava/lang/Object;

    iput-object p4, p0, Llyiahf/vczjk/gv0;->OooOOoo:Ljava/lang/Object;

    iput-object p5, p0, Llyiahf/vczjk/gv0;->OooOo00:Ljava/lang/Object;

    iput-boolean p6, p0, Llyiahf/vczjk/gv0;->OooOOO:Z

    iput-object p7, p0, Llyiahf/vczjk/gv0;->OooOo0:Ljava/lang/Object;

    iput p8, p0, Llyiahf/vczjk/gv0;->OooOOOO:I

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 10

    iget v0, p0, Llyiahf/vczjk/gv0;->OooOOO0:I

    packed-switch v0, :pswitch_data_0

    move-object v8, p1

    check-cast v8, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Integer;

    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    iget p1, p0, Llyiahf/vczjk/gv0;->OooOOOO:I

    or-int/lit8 p1, p1, 0x1

    invoke-static {p1}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result v9

    iget-object p1, p0, Llyiahf/vczjk/gv0;->OooOOOo:Ljava/lang/Object;

    move-object v1, p1

    check-cast v1, Llyiahf/vczjk/cs8;

    iget-object p1, p0, Llyiahf/vczjk/gv0;->OooOo00:Ljava/lang/Object;

    move-object v6, p1

    check-cast v6, Llyiahf/vczjk/a91;

    iget-object p1, p0, Llyiahf/vczjk/gv0;->OooOo0:Ljava/lang/Object;

    move-object v7, p1

    check-cast v7, Llyiahf/vczjk/a91;

    iget-object p1, p0, Llyiahf/vczjk/gv0;->OooOOo0:Ljava/lang/Object;

    move-object v2, p1

    check-cast v2, Llyiahf/vczjk/hl5;

    iget-boolean v3, p0, Llyiahf/vczjk/gv0;->OooOOO:Z

    iget-object p1, p0, Llyiahf/vczjk/gv0;->OooOOo:Ljava/lang/Object;

    move-object v4, p1

    check-cast v4, Llyiahf/vczjk/ir8;

    iget-object p1, p0, Llyiahf/vczjk/gv0;->OooOOoo:Ljava/lang/Object;

    move-object v5, p1

    check-cast v5, Llyiahf/vczjk/rr5;

    invoke-static/range {v1 .. v9}, Llyiahf/vczjk/as8;->OooO0OO(Llyiahf/vczjk/cs8;Llyiahf/vczjk/hl5;ZLlyiahf/vczjk/ir8;Llyiahf/vczjk/rr5;Llyiahf/vczjk/a91;Llyiahf/vczjk/a91;Llyiahf/vczjk/rf1;I)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :pswitch_0
    move-object v7, p1

    check-cast v7, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Integer;

    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    iget p1, p0, Llyiahf/vczjk/gv0;->OooOOOO:I

    or-int/lit8 p1, p1, 0x1

    invoke-static {p1}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result v8

    iget-object p1, p0, Llyiahf/vczjk/gv0;->OooOOOo:Ljava/lang/Object;

    move-object v0, p1

    check-cast v0, Llyiahf/vczjk/gt9;

    iget-object p1, p0, Llyiahf/vczjk/gv0;->OooOOo:Ljava/lang/Object;

    move-object v2, p1

    check-cast v2, Llyiahf/vczjk/h79;

    iget-object p1, p0, Llyiahf/vczjk/gv0;->OooOOoo:Ljava/lang/Object;

    move-object v3, p1

    check-cast v3, Llyiahf/vczjk/h79;

    iget-boolean v5, p0, Llyiahf/vczjk/gv0;->OooOOO:Z

    iget-object p1, p0, Llyiahf/vczjk/gv0;->OooOo0:Ljava/lang/Object;

    move-object v6, p1

    check-cast v6, Llyiahf/vczjk/cv0;

    iget-object p1, p0, Llyiahf/vczjk/gv0;->OooOOo0:Ljava/lang/Object;

    move-object v1, p1

    check-cast v1, Llyiahf/vczjk/le3;

    iget-object p1, p0, Llyiahf/vczjk/gv0;->OooOo00:Ljava/lang/Object;

    move-object v4, p1

    check-cast v4, Llyiahf/vczjk/kl5;

    invoke-static/range {v0 .. v8}, Llyiahf/vczjk/jv0;->OooO0OO(Llyiahf/vczjk/gt9;Llyiahf/vczjk/le3;Llyiahf/vczjk/h79;Llyiahf/vczjk/h79;Llyiahf/vczjk/kl5;ZLlyiahf/vczjk/cv0;Llyiahf/vczjk/rf1;I)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
