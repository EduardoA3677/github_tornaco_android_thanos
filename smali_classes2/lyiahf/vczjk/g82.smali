.class public final synthetic Llyiahf/vczjk/g82;
.super Llyiahf/vczjk/h1;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field public final synthetic OooOOO0:I


# direct methods
.method public synthetic constructor <init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V
    .locals 0

    iput p7, p0, Llyiahf/vczjk/g82;->OooOOO0:I

    move-object p7, p4

    move-object p4, p3

    move p3, p6

    move-object p6, p7

    move-object p7, p5

    move-object p5, p2

    move p2, p1

    move-object p1, p0

    invoke-direct/range {p1 .. p7}, Llyiahf/vczjk/h1;-><init>(IILjava/lang/Class;Ljava/lang/Object;Ljava/lang/String;Ljava/lang/String;)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    iget v0, p0, Llyiahf/vczjk/g82;->OooOOO0:I

    packed-switch v0, :pswitch_data_0

    check-cast p1, Llyiahf/vczjk/c98;

    iget-object v0, p0, Llyiahf/vczjk/h1;->receiver:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/ws5;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/ws5;->OooO0O0(Ljava/lang/Object;)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :pswitch_0
    check-cast p1, Llyiahf/vczjk/hd7;

    const-string v0, "p0"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v0, p0, Llyiahf/vczjk/h1;->receiver:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/t3a;

    const/4 v1, 0x1

    invoke-virtual {v0, p1, v1}, Llyiahf/vczjk/t3a;->OooO0Oo(Llyiahf/vczjk/hd7;Z)Llyiahf/vczjk/dp8;

    move-result-object p1

    return-object p1

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
