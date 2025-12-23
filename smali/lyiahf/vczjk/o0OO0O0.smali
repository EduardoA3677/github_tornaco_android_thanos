.class public final synthetic Llyiahf/vczjk/o0OO0O0;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/bf3;


# instance fields
.field public final synthetic OooOOO0:I


# direct methods
.method public synthetic constructor <init>(I)V
    .locals 0

    iput p1, p0, Llyiahf/vczjk/o0OO0O0;->OooOOO0:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final OooO0o0(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 6

    iget v0, p0, Llyiahf/vczjk/o0OO0O0;->OooOOO0:I

    packed-switch v0, :pswitch_data_0

    check-cast p1, Ljava/lang/Integer;

    invoke-virtual {p1}, Ljava/lang/Integer;->intValue()I

    move-result p1

    check-cast p2, Ljava/lang/String;

    check-cast p3, Ljava/lang/String;

    invoke-static {p1, p2, p3}, Ltornaco/app/thanox/lite/service/api/ShizukuServiceStub;->OooO0oO(ILjava/lang/String;Ljava/lang/String;)Llyiahf/vczjk/z8a;

    move-result-object p1

    return-object p1

    :pswitch_0
    check-cast p1, Ljava/lang/Integer;

    invoke-virtual {p1}, Ljava/lang/Integer;->intValue()I

    move-result p1

    check-cast p2, Ljava/lang/String;

    check-cast p3, Ljava/lang/String;

    invoke-static {p1, p2, p3}, Lgithub/tornaco/android/thanos/core/LoggerKt;->OooO00o(ILjava/lang/String;Ljava/lang/String;)Llyiahf/vczjk/z8a;

    move-result-object p1

    return-object p1

    :pswitch_1
    check-cast p1, Ljava/lang/Integer;

    invoke-virtual {p1}, Ljava/lang/Integer;->intValue()I

    move-result p1

    check-cast p2, Ljava/lang/String;

    check-cast p3, Ljava/lang/String;

    const-string v0, "tag"

    invoke-static {p2, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "msg"

    invoke-static {p3, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const/4 v0, 0x4

    const-string v1, " "

    if-eq p1, v0, :cond_2

    const/4 v0, 0x5

    if-eq p1, v0, :cond_1

    const/4 v0, 0x6

    if-eq p1, v0, :cond_0

    goto :goto_0

    :cond_0
    new-instance p1, Ljava/lang/StringBuilder;

    invoke-direct {p1}, Ljava/lang/StringBuilder;-><init>()V

    invoke-virtual {p1, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {p1, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {p1, p3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p1

    invoke-static {p1}, Llyiahf/vczjk/zsa;->Oooo0O0(Ljava/lang/String;)V

    goto :goto_0

    :cond_1
    new-instance p1, Ljava/lang/StringBuilder;

    invoke-direct {p1}, Ljava/lang/StringBuilder;-><init>()V

    invoke-virtual {p1, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {p1, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {p1, p3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p1

    invoke-static {p1}, Llyiahf/vczjk/zsa;->o0ooOOo(Ljava/lang/String;)V

    goto :goto_0

    :cond_2
    new-instance p1, Ljava/lang/StringBuilder;

    invoke-direct {p1}, Ljava/lang/StringBuilder;-><init>()V

    invoke-virtual {p1, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {p1, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {p1, p3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p1

    invoke-static {p1}, Llyiahf/vczjk/zsa;->Ooooo0o(Ljava/lang/String;)V

    :goto_0
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :pswitch_2
    move-object v0, p1

    check-cast v0, Llyiahf/vczjk/nf5;

    check-cast p2, Llyiahf/vczjk/ef5;

    check-cast p3, Llyiahf/vczjk/rk1;

    iget-wide v1, p3, Llyiahf/vczjk/rk1;->OooO00o:J

    invoke-interface {p2, v1, v2}, Llyiahf/vczjk/ef5;->OooOoOO(J)Llyiahf/vczjk/ow6;

    move-result-object p1

    iget v1, p1, Llyiahf/vczjk/ow6;->OooOOO0:I

    iget v2, p1, Llyiahf/vczjk/ow6;->OooOOO:I

    new-instance v4, Llyiahf/vczjk/ow;

    const/4 p2, 0x7

    invoke-direct {v4, p2}, Llyiahf/vczjk/ow;-><init>(I)V

    new-instance v5, Llyiahf/vczjk/j50;

    const/4 p2, 0x0

    invoke-direct {v5, p1, p2}, Llyiahf/vczjk/j50;-><init>(Llyiahf/vczjk/ow6;I)V

    sget-object v3, Llyiahf/vczjk/bn2;->OooOOO0:Llyiahf/vczjk/bn2;

    invoke-interface/range {v0 .. v5}, Llyiahf/vczjk/nf5;->OooOo(IILjava/util/Map;Llyiahf/vczjk/ow;Llyiahf/vczjk/oe3;)Llyiahf/vczjk/mf5;

    move-result-object p1

    return-object p1

    :pswitch_3
    check-cast p1, Llyiahf/vczjk/nf5;

    check-cast p2, Llyiahf/vczjk/ef5;

    check-cast p3, Llyiahf/vczjk/rk1;

    sget v0, Llyiahf/vczjk/o0OO0o;->OooO0O0:F

    invoke-interface {p1, v0}, Llyiahf/vczjk/f62;->o00Oo0(F)I

    move-result v0

    iget-wide v1, p3, Llyiahf/vczjk/rk1;->OooO00o:J

    mul-int/lit8 p3, v0, 0x2

    const/4 v3, 0x0

    invoke-static {v3, p3, v1, v2}, Llyiahf/vczjk/uk1;->OooO(IIJ)J

    move-result-wide v1

    invoke-interface {p2, v1, v2}, Llyiahf/vczjk/ef5;->OooOoOO(J)Llyiahf/vczjk/ow6;

    move-result-object p2

    iget v1, p2, Llyiahf/vczjk/ow6;->OooOOO:I

    sub-int/2addr v1, p3

    iget p3, p2, Llyiahf/vczjk/ow6;->OooOOO0:I

    new-instance v2, Llyiahf/vczjk/o0OO0o00;

    const/4 v3, 0x0

    invoke-direct {v2, p2, v0, v3}, Llyiahf/vczjk/o0OO0o00;-><init>(Llyiahf/vczjk/ow6;II)V

    sget-object p2, Llyiahf/vczjk/bn2;->OooOOO0:Llyiahf/vczjk/bn2;

    invoke-interface {p1, p3, v1, p2, v2}, Llyiahf/vczjk/nf5;->Oooo(IILjava/util/Map;Llyiahf/vczjk/oe3;)Llyiahf/vczjk/mf5;

    move-result-object p1

    return-object p1

    :pswitch_4
    check-cast p1, Llyiahf/vczjk/nf5;

    check-cast p2, Llyiahf/vczjk/ef5;

    check-cast p3, Llyiahf/vczjk/rk1;

    sget v0, Llyiahf/vczjk/o0OO0o;->OooO00o:F

    invoke-interface {p1, v0}, Llyiahf/vczjk/f62;->o00Oo0(F)I

    move-result v0

    iget-wide v1, p3, Llyiahf/vczjk/rk1;->OooO00o:J

    mul-int/lit8 p3, v0, 0x2

    const/4 v3, 0x0

    invoke-static {p3, v3, v1, v2}, Llyiahf/vczjk/uk1;->OooO(IIJ)J

    move-result-wide v1

    invoke-interface {p2, v1, v2}, Llyiahf/vczjk/ef5;->OooOoOO(J)Llyiahf/vczjk/ow6;

    move-result-object p2

    iget v1, p2, Llyiahf/vczjk/ow6;->OooOOO:I

    iget v2, p2, Llyiahf/vczjk/ow6;->OooOOO0:I

    sub-int/2addr v2, p3

    new-instance p3, Llyiahf/vczjk/o0OO0o00;

    const/4 v3, 0x1

    invoke-direct {p3, p2, v0, v3}, Llyiahf/vczjk/o0OO0o00;-><init>(Llyiahf/vczjk/ow6;II)V

    sget-object p2, Llyiahf/vczjk/bn2;->OooOOO0:Llyiahf/vczjk/bn2;

    invoke-interface {p1, v2, v1, p2, p3}, Llyiahf/vczjk/nf5;->Oooo(IILjava/util/Map;Llyiahf/vczjk/oe3;)Llyiahf/vczjk/mf5;

    move-result-object p1

    return-object p1

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
