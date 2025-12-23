.class public final synthetic Llyiahf/vczjk/ue5;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field public final synthetic OooOOO:Llyiahf/vczjk/x21;

.field public final synthetic OooOOO0:I

.field public final synthetic OooOOOO:Llyiahf/vczjk/al8;

.field public final synthetic OooOOOo:Llyiahf/vczjk/n6a;

.field public final synthetic OooOOo0:Llyiahf/vczjk/a91;


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/x21;Llyiahf/vczjk/al8;Llyiahf/vczjk/n6a;Llyiahf/vczjk/a91;II)V
    .locals 0

    iput p6, p0, Llyiahf/vczjk/ue5;->OooOOO0:I

    iput-object p1, p0, Llyiahf/vczjk/ue5;->OooOOO:Llyiahf/vczjk/x21;

    iput-object p2, p0, Llyiahf/vczjk/ue5;->OooOOOO:Llyiahf/vczjk/al8;

    iput-object p3, p0, Llyiahf/vczjk/ue5;->OooOOOo:Llyiahf/vczjk/n6a;

    iput-object p4, p0, Llyiahf/vczjk/ue5;->OooOOo0:Llyiahf/vczjk/a91;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 7

    iget v0, p0, Llyiahf/vczjk/ue5;->OooOOO0:I

    packed-switch v0, :pswitch_data_0

    move-object v5, p1

    check-cast v5, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Integer;

    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    const/16 p1, 0xc01

    invoke-static {p1}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result v6

    iget-object v4, p0, Llyiahf/vczjk/ue5;->OooOOo0:Llyiahf/vczjk/a91;

    iget-object v1, p0, Llyiahf/vczjk/ue5;->OooOOO:Llyiahf/vczjk/x21;

    iget-object v2, p0, Llyiahf/vczjk/ue5;->OooOOOO:Llyiahf/vczjk/al8;

    iget-object v3, p0, Llyiahf/vczjk/ue5;->OooOOOo:Llyiahf/vczjk/n6a;

    invoke-static/range {v1 .. v6}, Llyiahf/vczjk/we5;->OooO0OO(Llyiahf/vczjk/x21;Llyiahf/vczjk/al8;Llyiahf/vczjk/n6a;Llyiahf/vczjk/a91;Llyiahf/vczjk/rf1;I)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :pswitch_0
    move-object v4, p1

    check-cast v4, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Integer;

    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    const/16 p1, 0x6c01

    invoke-static {p1}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result v5

    iget-object v3, p0, Llyiahf/vczjk/ue5;->OooOOo0:Llyiahf/vczjk/a91;

    iget-object v0, p0, Llyiahf/vczjk/ue5;->OooOOO:Llyiahf/vczjk/x21;

    iget-object v1, p0, Llyiahf/vczjk/ue5;->OooOOOO:Llyiahf/vczjk/al8;

    iget-object v2, p0, Llyiahf/vczjk/ue5;->OooOOOo:Llyiahf/vczjk/n6a;

    invoke-static/range {v0 .. v5}, Llyiahf/vczjk/we5;->OooO00o(Llyiahf/vczjk/x21;Llyiahf/vczjk/al8;Llyiahf/vczjk/n6a;Llyiahf/vczjk/a91;Llyiahf/vczjk/rf1;I)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
