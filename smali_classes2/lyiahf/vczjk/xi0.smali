.class public final Llyiahf/vczjk/xi0;
.super Ljava/io/OutputStream;
.source "SourceFile"

# interfaces
.implements Ljava/lang/AutoCloseable;


# instance fields
.field public final synthetic OooOOO:Llyiahf/vczjk/mj0;

.field public final synthetic OooOOO0:I


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/mj0;I)V
    .locals 0

    iput p2, p0, Llyiahf/vczjk/xi0;->OooOOO0:I

    iput-object p1, p0, Llyiahf/vczjk/xi0;->OooOOO:Llyiahf/vczjk/mj0;

    invoke-direct {p0}, Ljava/io/OutputStream;-><init>()V

    return-void
.end method

.method private final OooO0Oo()V
    .locals 0

    return-void
.end method

.method private final OooO0oO()V
    .locals 0

    return-void
.end method


# virtual methods
.method public final close()V
    .locals 1

    iget v0, p0, Llyiahf/vczjk/xi0;->OooOOO0:I

    packed-switch v0, :pswitch_data_0

    iget-object v0, p0, Llyiahf/vczjk/xi0;->OooOOO:Llyiahf/vczjk/mj0;

    check-cast v0, Llyiahf/vczjk/hh7;

    invoke-virtual {v0}, Llyiahf/vczjk/hh7;->close()V

    :pswitch_0
    return-void

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final flush()V
    .locals 2

    iget v0, p0, Llyiahf/vczjk/xi0;->OooOOO0:I

    packed-switch v0, :pswitch_data_0

    iget-object v0, p0, Llyiahf/vczjk/xi0;->OooOOO:Llyiahf/vczjk/mj0;

    check-cast v0, Llyiahf/vczjk/hh7;

    iget-boolean v1, v0, Llyiahf/vczjk/hh7;->OooOOOO:Z

    if-nez v1, :cond_0

    invoke-virtual {v0}, Llyiahf/vczjk/hh7;->flush()V

    :cond_0
    :pswitch_0
    return-void

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final toString()Ljava/lang/String;
    .locals 2

    iget v0, p0, Llyiahf/vczjk/xi0;->OooOOO0:I

    packed-switch v0, :pswitch_data_0

    new-instance v0, Ljava/lang/StringBuilder;

    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    iget-object v1, p0, Llyiahf/vczjk/xi0;->OooOOO:Llyiahf/vczjk/mj0;

    check-cast v1, Llyiahf/vczjk/hh7;

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string v1, ".outputStream()"

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    return-object v0

    :pswitch_0
    new-instance v0, Ljava/lang/StringBuilder;

    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    iget-object v1, p0, Llyiahf/vczjk/xi0;->OooOOO:Llyiahf/vczjk/mj0;

    check-cast v1, Llyiahf/vczjk/yi0;

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string v1, ".outputStream()"

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    return-object v0

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final write(I)V
    .locals 2

    iget v0, p0, Llyiahf/vczjk/xi0;->OooOOO0:I

    packed-switch v0, :pswitch_data_0

    iget-object v0, p0, Llyiahf/vczjk/xi0;->OooOOO:Llyiahf/vczjk/mj0;

    check-cast v0, Llyiahf/vczjk/hh7;

    iget-boolean v1, v0, Llyiahf/vczjk/hh7;->OooOOOO:Z

    if-nez v1, :cond_0

    iget-object v1, v0, Llyiahf/vczjk/hh7;->OooOOO:Llyiahf/vczjk/yi0;

    int-to-byte p1, p1

    invoke-virtual {v1, p1}, Llyiahf/vczjk/yi0;->o0000O00(I)V

    invoke-virtual {v0}, Llyiahf/vczjk/hh7;->OooO0Oo()Llyiahf/vczjk/mj0;

    return-void

    :cond_0
    new-instance p1, Ljava/io/IOException;

    const-string v0, "closed"

    invoke-direct {p1, v0}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    throw p1

    :pswitch_0
    iget-object v0, p0, Llyiahf/vczjk/xi0;->OooOOO:Llyiahf/vczjk/mj0;

    check-cast v0, Llyiahf/vczjk/yi0;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/yi0;->o0000O00(I)V

    return-void

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final write([BII)V
    .locals 2

    iget v0, p0, Llyiahf/vczjk/xi0;->OooOOO0:I

    packed-switch v0, :pswitch_data_0

    const-string v0, "data"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v0, p0, Llyiahf/vczjk/xi0;->OooOOO:Llyiahf/vczjk/mj0;

    check-cast v0, Llyiahf/vczjk/hh7;

    iget-boolean v1, v0, Llyiahf/vczjk/hh7;->OooOOOO:Z

    if-nez v1, :cond_0

    iget-object v1, v0, Llyiahf/vczjk/hh7;->OooOOO:Llyiahf/vczjk/yi0;

    invoke-virtual {v1, p1, p2, p3}, Llyiahf/vczjk/yi0;->o00000oo([BII)V

    invoke-virtual {v0}, Llyiahf/vczjk/hh7;->OooO0Oo()Llyiahf/vczjk/mj0;

    return-void

    :cond_0
    new-instance p1, Ljava/io/IOException;

    const-string p2, "closed"

    invoke-direct {p1, p2}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    throw p1

    :pswitch_0
    const-string v0, "data"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v0, p0, Llyiahf/vczjk/xi0;->OooOOO:Llyiahf/vczjk/mj0;

    check-cast v0, Llyiahf/vczjk/yi0;

    invoke-virtual {v0, p1, p2, p3}, Llyiahf/vczjk/yi0;->o00000oo([BII)V

    return-void

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
