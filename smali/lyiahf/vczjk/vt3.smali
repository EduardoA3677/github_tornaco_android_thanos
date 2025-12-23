.class public final synthetic Llyiahf/vczjk/vt3;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field public final synthetic OooOOO:Ljava/lang/String;

.field public final synthetic OooOOO0:I

.field public final synthetic OooOOOO:Ljava/lang/Object;

.field public final synthetic OooOOOo:J

.field public final synthetic OooOOo:I

.field public final synthetic OooOOo0:I

.field public final synthetic OooOOoo:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/Object;Ljava/lang/String;Llyiahf/vczjk/kl5;JIII)V
    .locals 0

    iput p8, p0, Llyiahf/vczjk/vt3;->OooOOO0:I

    iput-object p1, p0, Llyiahf/vczjk/vt3;->OooOOoo:Ljava/lang/Object;

    iput-object p2, p0, Llyiahf/vczjk/vt3;->OooOOO:Ljava/lang/String;

    iput-object p3, p0, Llyiahf/vczjk/vt3;->OooOOOO:Ljava/lang/Object;

    iput-wide p4, p0, Llyiahf/vczjk/vt3;->OooOOOo:J

    iput p6, p0, Llyiahf/vczjk/vt3;->OooOOo0:I

    iput p7, p0, Llyiahf/vczjk/vt3;->OooOOo:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(Ljava/lang/String;JLlyiahf/vczjk/ze3;Llyiahf/vczjk/le3;II)V
    .locals 1

    const/4 v0, 0x2

    iput v0, p0, Llyiahf/vczjk/vt3;->OooOOO0:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/vt3;->OooOOO:Ljava/lang/String;

    iput-wide p2, p0, Llyiahf/vczjk/vt3;->OooOOOo:J

    iput-object p4, p0, Llyiahf/vczjk/vt3;->OooOOoo:Ljava/lang/Object;

    iput-object p5, p0, Llyiahf/vczjk/vt3;->OooOOOO:Ljava/lang/Object;

    iput p6, p0, Llyiahf/vczjk/vt3;->OooOOo0:I

    iput p7, p0, Llyiahf/vczjk/vt3;->OooOOo:I

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 9

    iget v0, p0, Llyiahf/vczjk/vt3;->OooOOO0:I

    packed-switch v0, :pswitch_data_0

    move-object v6, p1

    check-cast v6, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Integer;

    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    iget p1, p0, Llyiahf/vczjk/vt3;->OooOOo0:I

    or-int/lit8 p1, p1, 0x1

    invoke-static {p1}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result v7

    iget-object p1, p0, Llyiahf/vczjk/vt3;->OooOOOO:Ljava/lang/Object;

    move-object v5, p1

    check-cast v5, Llyiahf/vczjk/le3;

    iget v8, p0, Llyiahf/vczjk/vt3;->OooOOo:I

    iget-object v1, p0, Llyiahf/vczjk/vt3;->OooOOO:Ljava/lang/String;

    iget-wide v2, p0, Llyiahf/vczjk/vt3;->OooOOOo:J

    iget-object p1, p0, Llyiahf/vczjk/vt3;->OooOOoo:Ljava/lang/Object;

    move-object v4, p1

    check-cast v4, Llyiahf/vczjk/ze3;

    invoke-static/range {v1 .. v8}, Llyiahf/vczjk/br6;->OooO0o(Ljava/lang/String;JLlyiahf/vczjk/ze3;Llyiahf/vczjk/le3;Llyiahf/vczjk/rf1;II)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :pswitch_0
    move-object v5, p1

    check-cast v5, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Integer;

    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    iget p1, p0, Llyiahf/vczjk/vt3;->OooOOo0:I

    or-int/lit8 p1, p1, 0x1

    invoke-static {p1}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result v6

    iget-wide v3, p0, Llyiahf/vczjk/vt3;->OooOOOo:J

    iget v7, p0, Llyiahf/vczjk/vt3;->OooOOo:I

    iget-object p1, p0, Llyiahf/vczjk/vt3;->OooOOoo:Ljava/lang/Object;

    move-object v0, p1

    check-cast v0, Llyiahf/vczjk/un6;

    iget-object v1, p0, Llyiahf/vczjk/vt3;->OooOOO:Ljava/lang/String;

    iget-object p1, p0, Llyiahf/vczjk/vt3;->OooOOOO:Ljava/lang/Object;

    move-object v2, p1

    check-cast v2, Llyiahf/vczjk/kl5;

    invoke-static/range {v0 .. v7}, Llyiahf/vczjk/yt3;->OooO0O0(Llyiahf/vczjk/un6;Ljava/lang/String;Llyiahf/vczjk/kl5;JLlyiahf/vczjk/rf1;II)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :pswitch_1
    move-object v5, p1

    check-cast v5, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Integer;

    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    iget p1, p0, Llyiahf/vczjk/vt3;->OooOOo0:I

    or-int/lit8 p1, p1, 0x1

    invoke-static {p1}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result v6

    iget-wide v3, p0, Llyiahf/vczjk/vt3;->OooOOOo:J

    iget v7, p0, Llyiahf/vczjk/vt3;->OooOOo:I

    iget-object p1, p0, Llyiahf/vczjk/vt3;->OooOOoo:Ljava/lang/Object;

    move-object v0, p1

    check-cast v0, Llyiahf/vczjk/qv3;

    iget-object v1, p0, Llyiahf/vczjk/vt3;->OooOOO:Ljava/lang/String;

    iget-object p1, p0, Llyiahf/vczjk/vt3;->OooOOOO:Ljava/lang/Object;

    move-object v2, p1

    check-cast v2, Llyiahf/vczjk/kl5;

    invoke-static/range {v0 .. v7}, Llyiahf/vczjk/yt3;->OooO00o(Llyiahf/vczjk/qv3;Ljava/lang/String;Llyiahf/vczjk/kl5;JLlyiahf/vczjk/rf1;II)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
