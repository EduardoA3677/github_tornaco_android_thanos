.class public final synthetic Llyiahf/vczjk/lv5;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field public final synthetic OooOOO:J

.field public final synthetic OooOOO0:I

.field public final synthetic OooOOOO:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(JLlyiahf/vczjk/a91;I)V
    .locals 0

    const/4 p4, 0x1

    iput p4, p0, Llyiahf/vczjk/lv5;->OooOOO0:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-wide p1, p0, Llyiahf/vczjk/lv5;->OooOOO:J

    iput-object p3, p0, Llyiahf/vczjk/lv5;->OooOOOO:Ljava/lang/Object;

    return-void
.end method

.method public synthetic constructor <init>(Ljava/lang/Object;JII)V
    .locals 0

    iput p5, p0, Llyiahf/vczjk/lv5;->OooOOO0:I

    iput-object p1, p0, Llyiahf/vczjk/lv5;->OooOOOO:Ljava/lang/Object;

    iput-wide p2, p0, Llyiahf/vczjk/lv5;->OooOOO:J

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 3

    iget v0, p0, Llyiahf/vczjk/lv5;->OooOOO0:I

    check-cast p1, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Integer;

    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    packed-switch v0, :pswitch_data_0

    const/4 p2, 0x1

    invoke-static {p2}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result p2

    iget-object v0, p0, Llyiahf/vczjk/lv5;->OooOOOO:Ljava/lang/Object;

    check-cast v0, Ljava/lang/String;

    iget-wide v1, p0, Llyiahf/vczjk/lv5;->OooOOO:J

    invoke-static {v0, v1, v2, p1, p2}, Llyiahf/vczjk/ll6;->OooO00o(Ljava/lang/String;JLlyiahf/vczjk/rf1;I)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :pswitch_0
    const/4 p2, 0x1

    invoke-static {p2}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result p2

    iget-wide v0, p0, Llyiahf/vczjk/lv5;->OooOOO:J

    iget-object v2, p0, Llyiahf/vczjk/lv5;->OooOOOO:Ljava/lang/Object;

    check-cast v2, Llyiahf/vczjk/a91;

    invoke-static {v0, v1, v2, p1, p2}, Llyiahf/vczjk/wi9;->OooO0OO(JLlyiahf/vczjk/a91;Llyiahf/vczjk/rf1;I)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :pswitch_1
    const/4 p2, 0x1

    invoke-static {p2}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result p2

    iget-object v0, p0, Llyiahf/vczjk/lv5;->OooOOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/xf5;

    iget-wide v1, p0, Llyiahf/vczjk/lv5;->OooOOO:J

    invoke-static {v0, v1, v2, p1, p2}, Llyiahf/vczjk/tg0;->OooOOO(Llyiahf/vczjk/xf5;JLlyiahf/vczjk/rf1;I)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
