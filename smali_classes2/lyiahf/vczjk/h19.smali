.class public final synthetic Llyiahf/vczjk/h19;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field public final synthetic OooOOO:Llyiahf/vczjk/le3;

.field public final synthetic OooOOO0:I

.field public final synthetic OooOOOO:Llyiahf/vczjk/oe3;

.field public final synthetic OooOOOo:Llyiahf/vczjk/le3;


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/le3;Llyiahf/vczjk/oe3;Llyiahf/vczjk/le3;II)V
    .locals 0

    iput p5, p0, Llyiahf/vczjk/h19;->OooOOO0:I

    iput-object p1, p0, Llyiahf/vczjk/h19;->OooOOO:Llyiahf/vczjk/le3;

    iput-object p2, p0, Llyiahf/vczjk/h19;->OooOOOO:Llyiahf/vczjk/oe3;

    iput-object p3, p0, Llyiahf/vczjk/h19;->OooOOOo:Llyiahf/vczjk/le3;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 3

    iget v0, p0, Llyiahf/vczjk/h19;->OooOOO0:I

    check-cast p1, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Integer;

    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    packed-switch v0, :pswitch_data_0

    const/16 p2, 0x1b1

    invoke-static {p2}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result p2

    iget-object v0, p0, Llyiahf/vczjk/h19;->OooOOOO:Llyiahf/vczjk/oe3;

    iget-object v1, p0, Llyiahf/vczjk/h19;->OooOOOo:Llyiahf/vczjk/le3;

    iget-object v2, p0, Llyiahf/vczjk/h19;->OooOOO:Llyiahf/vczjk/le3;

    invoke-static {v2, v0, v1, p1, p2}, Llyiahf/vczjk/tp6;->OooO0oO(Llyiahf/vczjk/le3;Llyiahf/vczjk/oe3;Llyiahf/vczjk/le3;Llyiahf/vczjk/rf1;I)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :pswitch_0
    const/4 p2, 0x1

    invoke-static {p2}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result p2

    iget-object v0, p0, Llyiahf/vczjk/h19;->OooOOOO:Llyiahf/vczjk/oe3;

    iget-object v1, p0, Llyiahf/vczjk/h19;->OooOOOo:Llyiahf/vczjk/le3;

    iget-object v2, p0, Llyiahf/vczjk/h19;->OooOOO:Llyiahf/vczjk/le3;

    invoke-static {v2, v0, v1, p1, p2}, Llyiahf/vczjk/er8;->OooO(Llyiahf/vczjk/le3;Llyiahf/vczjk/oe3;Llyiahf/vczjk/le3;Llyiahf/vczjk/rf1;I)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
