.class public final synthetic Llyiahf/vczjk/iu;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field public final synthetic OooOOO:Ljava/lang/Object;

.field public final synthetic OooOOO0:I

.field public final synthetic OooOOOO:Ljava/lang/Object;

.field public final synthetic OooOOOo:I

.field public final synthetic OooOOo0:I


# direct methods
.method public synthetic constructor <init>(ILjava/lang/Object;IILjava/lang/Object;)V
    .locals 0

    iput p4, p0, Llyiahf/vczjk/iu;->OooOOO0:I

    iput-object p2, p0, Llyiahf/vczjk/iu;->OooOOOO:Ljava/lang/Object;

    iput-object p5, p0, Llyiahf/vczjk/iu;->OooOOO:Ljava/lang/Object;

    iput p1, p0, Llyiahf/vczjk/iu;->OooOOOo:I

    iput p3, p0, Llyiahf/vczjk/iu;->OooOOo0:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(Ljava/lang/String;Llyiahf/vczjk/kl5;II)V
    .locals 1

    const/4 v0, 0x1

    iput v0, p0, Llyiahf/vczjk/iu;->OooOOO0:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/iu;->OooOOO:Ljava/lang/Object;

    iput-object p2, p0, Llyiahf/vczjk/iu;->OooOOOO:Ljava/lang/Object;

    iput p3, p0, Llyiahf/vczjk/iu;->OooOOOo:I

    iput p4, p0, Llyiahf/vczjk/iu;->OooOOo0:I

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 3

    iget v0, p0, Llyiahf/vczjk/iu;->OooOOO0:I

    check-cast p1, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Integer;

    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    packed-switch v0, :pswitch_data_0

    iget p2, p0, Llyiahf/vczjk/iu;->OooOOOo:I

    or-int/lit8 p2, p2, 0x1

    invoke-static {p2}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result p2

    iget-object v0, p0, Llyiahf/vczjk/iu;->OooOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/le3;

    iget v1, p0, Llyiahf/vczjk/iu;->OooOOo0:I

    iget-object v2, p0, Llyiahf/vczjk/iu;->OooOOOO:Ljava/lang/Object;

    check-cast v2, Llyiahf/vczjk/le3;

    invoke-static {v2, v0, p1, p2, v1}, Llyiahf/vczjk/rs;->OooO0O0(Llyiahf/vczjk/le3;Llyiahf/vczjk/le3;Llyiahf/vczjk/rf1;II)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :pswitch_0
    iget p2, p0, Llyiahf/vczjk/iu;->OooOOOo:I

    or-int/lit8 p2, p2, 0x1

    invoke-static {p2}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result p2

    iget-object v0, p0, Llyiahf/vczjk/iu;->OooOOO:Ljava/lang/Object;

    check-cast v0, Ljava/lang/String;

    iget v1, p0, Llyiahf/vczjk/iu;->OooOOo0:I

    iget-object v2, p0, Llyiahf/vczjk/iu;->OooOOOO:Ljava/lang/Object;

    check-cast v2, Llyiahf/vczjk/kl5;

    invoke-static {p2, v1, v0, p1, v2}, Llyiahf/vczjk/kh6;->OooO0oO(IILjava/lang/String;Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :pswitch_1
    iget p2, p0, Llyiahf/vczjk/iu;->OooOOOo:I

    or-int/lit8 p2, p2, 0x1

    invoke-static {p2}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result p2

    iget-object v0, p0, Llyiahf/vczjk/iu;->OooOOO:Ljava/lang/Object;

    check-cast v0, Ljava/lang/String;

    iget v1, p0, Llyiahf/vczjk/iu;->OooOOo0:I

    iget-object v2, p0, Llyiahf/vczjk/iu;->OooOOOO:Ljava/lang/Object;

    check-cast v2, Llyiahf/vczjk/kl5;

    invoke-static {p2, v1, v0, p1, v2}, Llyiahf/vczjk/nqa;->OooO0oO(IILjava/lang/String;Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :pswitch_2
    iget p2, p0, Llyiahf/vczjk/iu;->OooOOOo:I

    or-int/lit8 p2, p2, 0x1

    invoke-static {p2}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result p2

    iget-object v0, p0, Llyiahf/vczjk/iu;->OooOOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/kl5;

    iget v1, p0, Llyiahf/vczjk/iu;->OooOOo0:I

    iget-object v2, p0, Llyiahf/vczjk/iu;->OooOOO:Ljava/lang/Object;

    check-cast v2, Ljava/lang/String;

    invoke-static {p2, v1, v2, p1, v0}, Llyiahf/vczjk/nqa;->OooO0o0(IILjava/lang/String;Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :pswitch_3
    iget p2, p0, Llyiahf/vczjk/iu;->OooOOOo:I

    or-int/lit8 p2, p2, 0x1

    invoke-static {p2}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result p2

    iget-object v0, p0, Llyiahf/vczjk/iu;->OooOOO:Ljava/lang/Object;

    check-cast v0, Ljava/lang/String;

    iget v1, p0, Llyiahf/vczjk/iu;->OooOOo0:I

    iget-object v2, p0, Llyiahf/vczjk/iu;->OooOOOO:Ljava/lang/Object;

    check-cast v2, Llyiahf/vczjk/kl5;

    invoke-static {p2, v1, v0, p1, v2}, Llyiahf/vczjk/os9;->OooO0O0(IILjava/lang/String;Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
