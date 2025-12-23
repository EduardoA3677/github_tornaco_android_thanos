.class public abstract Llyiahf/vczjk/im0;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Ljava/lang/Iterable;


# static fields
.field public static final OooOOO0:Llyiahf/vczjk/h25;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    new-instance v0, Llyiahf/vczjk/h25;

    const/4 v1, 0x0

    new-array v1, v1, [B

    invoke-direct {v0, v1}, Llyiahf/vczjk/h25;-><init>([B)V

    sput-object v0, Llyiahf/vczjk/im0;->OooOOO0:Llyiahf/vczjk/h25;

    return-void
.end method

.method public static OooO00o(Ljava/util/Iterator;I)Llyiahf/vczjk/im0;
    .locals 2

    const/4 v0, 0x1

    if-ne p1, v0, :cond_0

    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object p0

    check-cast p0, Llyiahf/vczjk/im0;

    return-object p0

    :cond_0
    ushr-int/lit8 v0, p1, 0x1

    invoke-static {p0, v0}, Llyiahf/vczjk/im0;->OooO00o(Ljava/util/Iterator;I)Llyiahf/vczjk/im0;

    move-result-object v1

    sub-int/2addr p1, v0

    invoke-static {p0, p1}, Llyiahf/vczjk/im0;->OooO00o(Ljava/util/Iterator;I)Llyiahf/vczjk/im0;

    move-result-object p0

    invoke-virtual {v1, p0}, Llyiahf/vczjk/im0;->OooO0O0(Llyiahf/vczjk/im0;)Llyiahf/vczjk/im0;

    move-result-object p0

    return-object p0
.end method

.method public static OooOO0O()Llyiahf/vczjk/hm0;
    .locals 1

    new-instance v0, Llyiahf/vczjk/hm0;

    invoke-direct {v0}, Llyiahf/vczjk/hm0;-><init>()V

    return-object v0
.end method


# virtual methods
.method public abstract OooO()Z
.end method

.method public final OooO0O0(Llyiahf/vczjk/im0;)Llyiahf/vczjk/im0;
    .locals 7

    invoke-virtual {p0}, Llyiahf/vczjk/im0;->size()I

    move-result v0

    invoke-virtual {p1}, Llyiahf/vczjk/im0;->size()I

    move-result v1

    int-to-long v2, v0

    int-to-long v4, v1

    add-long/2addr v2, v4

    const-wide/32 v4, 0x7fffffff

    cmp-long v2, v2, v4

    if-gez v2, :cond_8

    sget-object v0, Llyiahf/vczjk/jv7;->OooOo00:[I

    instance-of v0, p0, Llyiahf/vczjk/jv7;

    if-eqz v0, :cond_0

    move-object v0, p0

    check-cast v0, Llyiahf/vczjk/jv7;

    goto :goto_0

    :cond_0
    const/4 v0, 0x0

    :goto_0
    invoke-virtual {p1}, Llyiahf/vczjk/im0;->size()I

    move-result v1

    if-nez v1, :cond_1

    return-object p0

    :cond_1
    invoke-virtual {p0}, Llyiahf/vczjk/im0;->size()I

    move-result v1

    if-nez v1, :cond_2

    return-object p1

    :cond_2
    invoke-virtual {p0}, Llyiahf/vczjk/im0;->size()I

    move-result v1

    invoke-virtual {p1}, Llyiahf/vczjk/im0;->size()I

    move-result v2

    add-int/2addr v2, v1

    const/4 v1, 0x0

    const/16 v3, 0x80

    if-ge v2, v3, :cond_3

    invoke-virtual {p0}, Llyiahf/vczjk/im0;->size()I

    move-result v0

    invoke-virtual {p1}, Llyiahf/vczjk/im0;->size()I

    move-result v2

    add-int v3, v0, v2

    new-array v3, v3, [B

    invoke-virtual {p0, v3, v1, v1, v0}, Llyiahf/vczjk/im0;->OooO0OO([BIII)V

    invoke-virtual {p1, v3, v1, v0, v2}, Llyiahf/vczjk/im0;->OooO0OO([BIII)V

    new-instance p1, Llyiahf/vczjk/h25;

    invoke-direct {p1, v3}, Llyiahf/vczjk/h25;-><init>([B)V

    return-object p1

    :cond_3
    if-eqz v0, :cond_4

    iget-object v4, v0, Llyiahf/vczjk/jv7;->OooOOOo:Llyiahf/vczjk/im0;

    invoke-virtual {v4}, Llyiahf/vczjk/im0;->size()I

    move-result v5

    invoke-virtual {p1}, Llyiahf/vczjk/im0;->size()I

    move-result v6

    add-int/2addr v6, v5

    if-ge v6, v3, :cond_4

    invoke-virtual {v4}, Llyiahf/vczjk/im0;->size()I

    move-result v2

    invoke-virtual {p1}, Llyiahf/vczjk/im0;->size()I

    move-result v3

    add-int v5, v2, v3

    new-array v5, v5, [B

    invoke-virtual {v4, v5, v1, v1, v2}, Llyiahf/vczjk/im0;->OooO0OO([BIII)V

    invoke-virtual {p1, v5, v1, v2, v3}, Llyiahf/vczjk/im0;->OooO0OO([BIII)V

    new-instance p1, Llyiahf/vczjk/h25;

    invoke-direct {p1, v5}, Llyiahf/vczjk/h25;-><init>([B)V

    new-instance v1, Llyiahf/vczjk/jv7;

    iget-object v0, v0, Llyiahf/vczjk/jv7;->OooOOOO:Llyiahf/vczjk/im0;

    invoke-direct {v1, v0, p1}, Llyiahf/vczjk/jv7;-><init>(Llyiahf/vczjk/im0;Llyiahf/vczjk/im0;)V

    return-object v1

    :cond_4
    if-eqz v0, :cond_5

    iget-object v1, v0, Llyiahf/vczjk/jv7;->OooOOOO:Llyiahf/vczjk/im0;

    invoke-virtual {v1}, Llyiahf/vczjk/im0;->OooO0oo()I

    move-result v3

    iget-object v4, v0, Llyiahf/vczjk/jv7;->OooOOOo:Llyiahf/vczjk/im0;

    invoke-virtual {v4}, Llyiahf/vczjk/im0;->OooO0oo()I

    move-result v5

    if-le v3, v5, :cond_5

    invoke-virtual {p1}, Llyiahf/vczjk/im0;->OooO0oo()I

    move-result v3

    iget v0, v0, Llyiahf/vczjk/jv7;->OooOOo:I

    if-le v0, v3, :cond_5

    new-instance v0, Llyiahf/vczjk/jv7;

    invoke-direct {v0, v4, p1}, Llyiahf/vczjk/jv7;-><init>(Llyiahf/vczjk/im0;Llyiahf/vczjk/im0;)V

    new-instance p1, Llyiahf/vczjk/jv7;

    invoke-direct {p1, v1, v0}, Llyiahf/vczjk/jv7;-><init>(Llyiahf/vczjk/im0;Llyiahf/vczjk/im0;)V

    return-object p1

    :cond_5
    invoke-virtual {p0}, Llyiahf/vczjk/im0;->OooO0oo()I

    move-result v0

    invoke-virtual {p1}, Llyiahf/vczjk/im0;->OooO0oo()I

    move-result v1

    invoke-static {v0, v1}, Ljava/lang/Math;->max(II)I

    move-result v0

    add-int/lit8 v0, v0, 0x1

    sget-object v1, Llyiahf/vczjk/jv7;->OooOo00:[I

    aget v0, v1, v0

    if-lt v2, v0, :cond_6

    new-instance v0, Llyiahf/vczjk/jv7;

    invoke-direct {v0, p0, p1}, Llyiahf/vczjk/jv7;-><init>(Llyiahf/vczjk/im0;Llyiahf/vczjk/im0;)V

    return-object v0

    :cond_6
    new-instance v0, Llyiahf/vczjk/gv7;

    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    new-instance v1, Ljava/util/Stack;

    invoke-direct {v1}, Ljava/util/Stack;-><init>()V

    iput-object v1, v0, Llyiahf/vczjk/gv7;->OooOOO0:Ljava/lang/Object;

    invoke-virtual {v0, p0}, Llyiahf/vczjk/gv7;->OooO00o(Llyiahf/vczjk/im0;)V

    invoke-virtual {v0, p1}, Llyiahf/vczjk/gv7;->OooO00o(Llyiahf/vczjk/im0;)V

    iget-object p1, v0, Llyiahf/vczjk/gv7;->OooOOO0:Ljava/lang/Object;

    check-cast p1, Ljava/util/Stack;

    invoke-virtual {p1}, Ljava/util/Stack;->pop()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/im0;

    :goto_1
    invoke-virtual {p1}, Ljava/util/AbstractCollection;->isEmpty()Z

    move-result v1

    if-nez v1, :cond_7

    invoke-virtual {p1}, Ljava/util/Stack;->pop()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/im0;

    new-instance v2, Llyiahf/vczjk/jv7;

    invoke-direct {v2, v1, v0}, Llyiahf/vczjk/jv7;-><init>(Llyiahf/vczjk/im0;Llyiahf/vczjk/im0;)V

    move-object v0, v2

    goto :goto_1

    :cond_7
    return-object v0

    :cond_8
    new-instance p1, Ljava/lang/IllegalArgumentException;

    new-instance v2, Ljava/lang/StringBuilder;

    const/16 v3, 0x35

    invoke-direct {v2, v3}, Ljava/lang/StringBuilder;-><init>(I)V

    const-string v3, "ByteString would be too long: "

    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    const-string v0, "+"

    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v2, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    invoke-direct {p1, v0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p1
.end method

.method public final OooO0OO([BIII)V
    .locals 3

    const/16 v0, 0x1e

    if-ltz p2, :cond_5

    if-ltz p3, :cond_4

    if-ltz p4, :cond_3

    add-int v0, p2, p4

    invoke-virtual {p0}, Llyiahf/vczjk/im0;->size()I

    move-result v1

    const/16 v2, 0x22

    if-gt v0, v1, :cond_2

    add-int v0, p3, p4

    array-length v1, p1

    if-gt v0, v1, :cond_1

    if-lez p4, :cond_0

    invoke-virtual {p0, p1, p2, p3, p4}, Llyiahf/vczjk/im0;->OooO0o([BIII)V

    :cond_0
    return-void

    :cond_1
    new-instance p1, Ljava/lang/IndexOutOfBoundsException;

    new-instance p2, Ljava/lang/StringBuilder;

    invoke-direct {p2, v2}, Ljava/lang/StringBuilder;-><init>(I)V

    const-string p3, "Target end offset < 0: "

    invoke-virtual {p2, p3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {p2, v0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    invoke-virtual {p2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p2

    invoke-direct {p1, p2}, Ljava/lang/IndexOutOfBoundsException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_2
    new-instance p1, Ljava/lang/IndexOutOfBoundsException;

    new-instance p2, Ljava/lang/StringBuilder;

    invoke-direct {p2, v2}, Ljava/lang/StringBuilder;-><init>(I)V

    const-string p3, "Source end offset < 0: "

    invoke-virtual {p2, p3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {p2, v0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    invoke-virtual {p2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p2

    invoke-direct {p1, p2}, Ljava/lang/IndexOutOfBoundsException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_3
    new-instance p1, Ljava/lang/IndexOutOfBoundsException;

    new-instance p2, Ljava/lang/StringBuilder;

    const/16 p3, 0x17

    invoke-direct {p2, p3}, Ljava/lang/StringBuilder;-><init>(I)V

    const-string p3, "Length < 0: "

    invoke-virtual {p2, p3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {p2, p4}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    invoke-virtual {p2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p2

    invoke-direct {p1, p2}, Ljava/lang/IndexOutOfBoundsException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_4
    new-instance p1, Ljava/lang/IndexOutOfBoundsException;

    new-instance p2, Ljava/lang/StringBuilder;

    invoke-direct {p2, v0}, Ljava/lang/StringBuilder;-><init>(I)V

    const-string p4, "Target offset < 0: "

    invoke-virtual {p2, p4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {p2, p3}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    invoke-virtual {p2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p2

    invoke-direct {p1, p2}, Ljava/lang/IndexOutOfBoundsException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_5
    new-instance p1, Ljava/lang/IndexOutOfBoundsException;

    new-instance p3, Ljava/lang/StringBuilder;

    invoke-direct {p3, v0}, Ljava/lang/StringBuilder;-><init>(I)V

    const-string p4, "Source offset < 0: "

    invoke-virtual {p3, p4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {p3, p2}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    invoke-virtual {p3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p2

    invoke-direct {p1, p2}, Ljava/lang/IndexOutOfBoundsException;-><init>(Ljava/lang/String;)V

    throw p1
.end method

.method public abstract OooO0o([BIII)V
.end method

.method public abstract OooO0oo()I
.end method

.method public abstract OooOO0()Z
.end method

.method public abstract OooOO0o(III)I
.end method

.method public abstract OooOOO()I
.end method

.method public abstract OooOOO0(III)I
.end method

.method public abstract OooOOOO()Ljava/lang/String;
.end method

.method public final OooOOOo()Ljava/lang/String;
    .locals 3

    :try_start_0
    invoke-virtual {p0}, Llyiahf/vczjk/im0;->OooOOOO()Ljava/lang/String;

    move-result-object v0
    :try_end_0
    .catch Ljava/io/UnsupportedEncodingException; {:try_start_0 .. :try_end_0} :catch_0

    return-object v0

    :catch_0
    move-exception v0

    new-instance v1, Ljava/lang/RuntimeException;

    const-string v2, "UTF-8 not supported?"

    invoke-direct {v1, v2, v0}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;Ljava/lang/Throwable;)V

    throw v1
.end method

.method public abstract OooOOo0(Ljava/io/OutputStream;II)V
.end method

.method public abstract size()I
.end method

.method public final toString()Ljava/lang/String;
    .locals 2

    invoke-static {p0}, Ljava/lang/System;->identityHashCode(Ljava/lang/Object;)I

    move-result v0

    invoke-static {v0}, Ljava/lang/Integer;->toHexString(I)Ljava/lang/String;

    move-result-object v0

    invoke-virtual {p0}, Llyiahf/vczjk/im0;->size()I

    move-result v1

    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v1

    filled-new-array {v0, v1}, [Ljava/lang/Object;

    move-result-object v0

    const-string v1, "<ByteString@%s size=%d>"

    invoke-static {v1, v0}, Ljava/lang/String;->format(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method
