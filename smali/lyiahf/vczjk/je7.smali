.class public final synthetic Llyiahf/vczjk/je7;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field public final synthetic OooOOO:J

.field public final synthetic OooOOO0:I

.field public final synthetic OooOOOO:Llyiahf/vczjk/rn9;

.field public final synthetic OooOOOo:Llyiahf/vczjk/ze3;

.field public final synthetic OooOOo0:I


# direct methods
.method public synthetic constructor <init>(JLlyiahf/vczjk/rn9;Llyiahf/vczjk/ze3;II)V
    .locals 0

    iput p6, p0, Llyiahf/vczjk/je7;->OooOOO0:I

    iput-wide p1, p0, Llyiahf/vczjk/je7;->OooOOO:J

    iput-object p3, p0, Llyiahf/vczjk/je7;->OooOOOO:Llyiahf/vczjk/rn9;

    iput-object p4, p0, Llyiahf/vczjk/je7;->OooOOOo:Llyiahf/vczjk/ze3;

    iput p5, p0, Llyiahf/vczjk/je7;->OooOOo0:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 7

    iget v0, p0, Llyiahf/vczjk/je7;->OooOOO0:I

    packed-switch v0, :pswitch_data_0

    move-object v5, p1

    check-cast v5, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Integer;

    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    iget p1, p0, Llyiahf/vczjk/je7;->OooOOo0:I

    or-int/lit8 p1, p1, 0x1

    invoke-static {p1}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result v6

    iget-object v3, p0, Llyiahf/vczjk/je7;->OooOOOO:Llyiahf/vczjk/rn9;

    iget-object v4, p0, Llyiahf/vczjk/je7;->OooOOOo:Llyiahf/vczjk/ze3;

    iget-wide v1, p0, Llyiahf/vczjk/je7;->OooOOO:J

    invoke-static/range {v1 .. v6}, Llyiahf/vczjk/wi9;->OooO0O0(JLlyiahf/vczjk/rn9;Llyiahf/vczjk/ze3;Llyiahf/vczjk/rf1;I)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :pswitch_0
    move-object v4, p1

    check-cast v4, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Integer;

    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    iget p1, p0, Llyiahf/vczjk/je7;->OooOOo0:I

    or-int/lit8 p1, p1, 0x1

    invoke-static {p1}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result v5

    iget-wide v0, p0, Llyiahf/vczjk/je7;->OooOOO:J

    iget-object v2, p0, Llyiahf/vczjk/je7;->OooOOOO:Llyiahf/vczjk/rn9;

    iget-object v3, p0, Llyiahf/vczjk/je7;->OooOOOo:Llyiahf/vczjk/ze3;

    invoke-static/range {v0 .. v5}, Llyiahf/vczjk/tp6;->OooO0Oo(JLlyiahf/vczjk/rn9;Llyiahf/vczjk/ze3;Llyiahf/vczjk/rf1;I)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
