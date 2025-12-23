.class public final Llyiahf/vczjk/ul0;
.super Llyiahf/vczjk/a59;
.source "SourceFile"


# static fields
.field private static final serialVersionUID:J = 0x1L


# virtual methods
.method public final OooO0Oo(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)Ljava/lang/Object;
    .locals 0

    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object p1, Llyiahf/vczjk/a60;->OooO0O0:Llyiahf/vczjk/z50;

    invoke-virtual {p2, p1}, Llyiahf/vczjk/eb4;->OooOooo(Llyiahf/vczjk/z50;)[B

    move-result-object p1

    invoke-static {p1}, Ljava/nio/ByteBuffer;->wrap([B)Ljava/nio/ByteBuffer;

    move-result-object p1

    return-object p1
.end method

.method public final OooO0o0(Llyiahf/vczjk/eb4;Llyiahf/vczjk/v72;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    check-cast p3, Ljava/nio/ByteBuffer;

    new-instance v0, Llyiahf/vczjk/tl0;

    invoke-direct {v0, p3}, Llyiahf/vczjk/tl0;-><init>(Ljava/nio/ByteBuffer;)V

    invoke-virtual {p2}, Llyiahf/vczjk/v72;->o00oO0O()Llyiahf/vczjk/z50;

    move-result-object p2

    invoke-virtual {p1, p2, v0}, Llyiahf/vczjk/eb4;->o000(Llyiahf/vczjk/z50;Llyiahf/vczjk/tl0;)I

    invoke-virtual {v0}, Ljava/io/OutputStream;->close()V

    return-object p3
.end method
