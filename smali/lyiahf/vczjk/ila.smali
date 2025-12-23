.class public final synthetic Llyiahf/vczjk/ila;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field public final synthetic OooOOO:Llyiahf/vczjk/kl5;

.field public final synthetic OooOOO0:I

.field public final synthetic OooOOOO:J

.field public final synthetic OooOOOo:J

.field public final synthetic OooOOo:Llyiahf/vczjk/h79;

.field public final synthetic OooOOo0:Llyiahf/vczjk/h79;

.field public final synthetic OooOOoo:F

.field public final synthetic OooOo0:F

.field public final synthetic OooOo00:F

.field public final synthetic OooOo0O:F


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/kl5;JJLlyiahf/vczjk/h79;Llyiahf/vczjk/h79;FFFFII)V
    .locals 0

    iput p13, p0, Llyiahf/vczjk/ila;->OooOOO0:I

    iput-object p1, p0, Llyiahf/vczjk/ila;->OooOOO:Llyiahf/vczjk/kl5;

    iput-wide p2, p0, Llyiahf/vczjk/ila;->OooOOOO:J

    iput-wide p4, p0, Llyiahf/vczjk/ila;->OooOOOo:J

    iput-object p6, p0, Llyiahf/vczjk/ila;->OooOOo0:Llyiahf/vczjk/h79;

    iput-object p7, p0, Llyiahf/vczjk/ila;->OooOOo:Llyiahf/vczjk/h79;

    iput p8, p0, Llyiahf/vczjk/ila;->OooOOoo:F

    iput p9, p0, Llyiahf/vczjk/ila;->OooOo00:F

    iput p10, p0, Llyiahf/vczjk/ila;->OooOo0:F

    iput p11, p0, Llyiahf/vczjk/ila;->OooOo0O:F

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 14

    iget v0, p0, Llyiahf/vczjk/ila;->OooOOO0:I

    packed-switch v0, :pswitch_data_0

    move-object v12, p1

    check-cast v12, Llyiahf/vczjk/rf1;

    move-object/from16 p1, p2

    check-cast p1, Ljava/lang/Integer;

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    const/4 p1, 0x7

    invoke-static {p1}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result v13

    iget v10, p0, Llyiahf/vczjk/ila;->OooOo0:F

    iget v11, p0, Llyiahf/vczjk/ila;->OooOo0O:F

    iget-object v1, p0, Llyiahf/vczjk/ila;->OooOOO:Llyiahf/vczjk/kl5;

    iget-wide v2, p0, Llyiahf/vczjk/ila;->OooOOOO:J

    iget-wide v4, p0, Llyiahf/vczjk/ila;->OooOOOo:J

    iget-object v6, p0, Llyiahf/vczjk/ila;->OooOOo0:Llyiahf/vczjk/h79;

    iget-object v7, p0, Llyiahf/vczjk/ila;->OooOOo:Llyiahf/vczjk/h79;

    iget v8, p0, Llyiahf/vczjk/ila;->OooOOoo:F

    iget v9, p0, Llyiahf/vczjk/ila;->OooOo00:F

    invoke-static/range {v1 .. v13}, Llyiahf/vczjk/kla;->OooO0O0(Llyiahf/vczjk/kl5;JJLlyiahf/vczjk/h79;Llyiahf/vczjk/h79;FFFFLlyiahf/vczjk/rf1;I)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :pswitch_0
    move-object v11, p1

    check-cast v11, Llyiahf/vczjk/rf1;

    move-object/from16 p1, p2

    check-cast p1, Ljava/lang/Integer;

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    const/4 p1, 0x7

    invoke-static {p1}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result v12

    iget v9, p0, Llyiahf/vczjk/ila;->OooOo0:F

    iget v10, p0, Llyiahf/vczjk/ila;->OooOo0O:F

    iget-object v0, p0, Llyiahf/vczjk/ila;->OooOOO:Llyiahf/vczjk/kl5;

    iget-wide v1, p0, Llyiahf/vczjk/ila;->OooOOOO:J

    iget-wide v3, p0, Llyiahf/vczjk/ila;->OooOOOo:J

    iget-object v5, p0, Llyiahf/vczjk/ila;->OooOOo0:Llyiahf/vczjk/h79;

    iget-object v6, p0, Llyiahf/vczjk/ila;->OooOOo:Llyiahf/vczjk/h79;

    iget v7, p0, Llyiahf/vczjk/ila;->OooOOoo:F

    iget v8, p0, Llyiahf/vczjk/ila;->OooOo00:F

    invoke-static/range {v0 .. v12}, Llyiahf/vczjk/kla;->OooO00o(Llyiahf/vczjk/kl5;JJLlyiahf/vczjk/h79;Llyiahf/vczjk/h79;FFFFLlyiahf/vczjk/rf1;I)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
