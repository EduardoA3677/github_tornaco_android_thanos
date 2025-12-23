.class public final Llyiahf/vczjk/is7;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Ljava/io/Closeable;
.implements Ljava/lang/AutoCloseable;


# instance fields
.field public final OooOOO:Llyiahf/vczjk/fe7;

.field public final OooOOO0:Llyiahf/vczjk/lr;

.field public final OooOOOO:Ljava/lang/String;

.field public final OooOOOo:I

.field public final OooOOo:Llyiahf/vczjk/vm3;

.field public final OooOOo0:Llyiahf/vczjk/fm3;

.field public final OooOOoo:Llyiahf/vczjk/ks7;

.field public final OooOo:J

.field public final OooOo0:Llyiahf/vczjk/is7;

.field public final OooOo00:Llyiahf/vczjk/is7;

.field public final OooOo0O:Llyiahf/vczjk/is7;

.field public final OooOo0o:J

.field public OooOoO:Llyiahf/vczjk/pm0;

.field public final OooOoO0:Llyiahf/vczjk/qv0;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/lr;Llyiahf/vczjk/fe7;Ljava/lang/String;ILlyiahf/vczjk/fm3;Llyiahf/vczjk/vm3;Llyiahf/vczjk/ks7;Llyiahf/vczjk/is7;Llyiahf/vczjk/is7;Llyiahf/vczjk/is7;JJLlyiahf/vczjk/qv0;)V
    .locals 1

    const-string v0, "request"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "protocol"

    invoke-static {p2, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "message"

    invoke-static {p3, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/is7;->OooOOO0:Llyiahf/vczjk/lr;

    iput-object p2, p0, Llyiahf/vczjk/is7;->OooOOO:Llyiahf/vczjk/fe7;

    iput-object p3, p0, Llyiahf/vczjk/is7;->OooOOOO:Ljava/lang/String;

    iput p4, p0, Llyiahf/vczjk/is7;->OooOOOo:I

    iput-object p5, p0, Llyiahf/vczjk/is7;->OooOOo0:Llyiahf/vczjk/fm3;

    iput-object p6, p0, Llyiahf/vczjk/is7;->OooOOo:Llyiahf/vczjk/vm3;

    iput-object p7, p0, Llyiahf/vczjk/is7;->OooOOoo:Llyiahf/vczjk/ks7;

    iput-object p8, p0, Llyiahf/vczjk/is7;->OooOo00:Llyiahf/vczjk/is7;

    iput-object p9, p0, Llyiahf/vczjk/is7;->OooOo0:Llyiahf/vczjk/is7;

    iput-object p10, p0, Llyiahf/vczjk/is7;->OooOo0O:Llyiahf/vczjk/is7;

    iput-wide p11, p0, Llyiahf/vczjk/is7;->OooOo0o:J

    iput-wide p13, p0, Llyiahf/vczjk/is7;->OooOo:J

    move-object/from16 p1, p15

    iput-object p1, p0, Llyiahf/vczjk/is7;->OooOoO0:Llyiahf/vczjk/qv0;

    return-void
.end method

.method public static OooO0Oo(Ljava/lang/String;Llyiahf/vczjk/is7;)Ljava/lang/String;
    .locals 0

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    iget-object p1, p1, Llyiahf/vczjk/is7;->OooOOo:Llyiahf/vczjk/vm3;

    invoke-virtual {p1, p0}, Llyiahf/vczjk/vm3;->OooO00o(Ljava/lang/String;)Ljava/lang/String;

    move-result-object p0

    if-nez p0, :cond_0

    const/4 p0, 0x0

    :cond_0
    return-object p0
.end method


# virtual methods
.method public final OooO0oO()Z
    .locals 3

    const/16 v0, 0xc8

    const/4 v1, 0x0

    iget v2, p0, Llyiahf/vczjk/is7;->OooOOOo:I

    if-gt v0, v2, :cond_0

    const/16 v0, 0x12c

    if-ge v2, v0, :cond_0

    const/4 v0, 0x1

    return v0

    :cond_0
    return v1
.end method

.method public final OooOOOO()Llyiahf/vczjk/gs7;
    .locals 3

    new-instance v0, Llyiahf/vczjk/gs7;

    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    iget-object v1, p0, Llyiahf/vczjk/is7;->OooOOO0:Llyiahf/vczjk/lr;

    iput-object v1, v0, Llyiahf/vczjk/gs7;->OooO00o:Llyiahf/vczjk/lr;

    iget-object v1, p0, Llyiahf/vczjk/is7;->OooOOO:Llyiahf/vczjk/fe7;

    iput-object v1, v0, Llyiahf/vczjk/gs7;->OooO0O0:Llyiahf/vczjk/fe7;

    iget v1, p0, Llyiahf/vczjk/is7;->OooOOOo:I

    iput v1, v0, Llyiahf/vczjk/gs7;->OooO0OO:I

    iget-object v1, p0, Llyiahf/vczjk/is7;->OooOOOO:Ljava/lang/String;

    iput-object v1, v0, Llyiahf/vczjk/gs7;->OooO0Oo:Ljava/lang/String;

    iget-object v1, p0, Llyiahf/vczjk/is7;->OooOOo0:Llyiahf/vczjk/fm3;

    iput-object v1, v0, Llyiahf/vczjk/gs7;->OooO0o0:Llyiahf/vczjk/fm3;

    iget-object v1, p0, Llyiahf/vczjk/is7;->OooOOo:Llyiahf/vczjk/vm3;

    invoke-virtual {v1}, Llyiahf/vczjk/vm3;->OooO0o()Llyiahf/vczjk/oO0OOo0o;

    move-result-object v1

    iput-object v1, v0, Llyiahf/vczjk/gs7;->OooO0o:Llyiahf/vczjk/oO0OOo0o;

    iget-object v1, p0, Llyiahf/vczjk/is7;->OooOOoo:Llyiahf/vczjk/ks7;

    iput-object v1, v0, Llyiahf/vczjk/gs7;->OooO0oO:Llyiahf/vczjk/ks7;

    iget-object v1, p0, Llyiahf/vczjk/is7;->OooOo00:Llyiahf/vczjk/is7;

    iput-object v1, v0, Llyiahf/vczjk/gs7;->OooO0oo:Llyiahf/vczjk/is7;

    iget-object v1, p0, Llyiahf/vczjk/is7;->OooOo0:Llyiahf/vczjk/is7;

    iput-object v1, v0, Llyiahf/vczjk/gs7;->OooO:Llyiahf/vczjk/is7;

    iget-object v1, p0, Llyiahf/vczjk/is7;->OooOo0O:Llyiahf/vczjk/is7;

    iput-object v1, v0, Llyiahf/vczjk/gs7;->OooOO0:Llyiahf/vczjk/is7;

    iget-wide v1, p0, Llyiahf/vczjk/is7;->OooOo0o:J

    iput-wide v1, v0, Llyiahf/vczjk/gs7;->OooOO0O:J

    iget-wide v1, p0, Llyiahf/vczjk/is7;->OooOo:J

    iput-wide v1, v0, Llyiahf/vczjk/gs7;->OooOO0o:J

    iget-object v1, p0, Llyiahf/vczjk/is7;->OooOoO0:Llyiahf/vczjk/qv0;

    iput-object v1, v0, Llyiahf/vczjk/gs7;->OooOOO0:Llyiahf/vczjk/qv0;

    return-object v0
.end method

.method public final close()V
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/is7;->OooOOoo:Llyiahf/vczjk/ks7;

    if-eqz v0, :cond_0

    invoke-virtual {v0}, Llyiahf/vczjk/ks7;->close()V

    return-void

    :cond_0
    new-instance v0, Ljava/lang/IllegalStateException;

    const-string v1, "response is not eligible for a body and must not be closed"

    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw v0
.end method

.method public final toString()Ljava/lang/String;
    .locals 2

    new-instance v0, Ljava/lang/StringBuilder;

    const-string v1, "Response{protocol="

    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    iget-object v1, p0, Llyiahf/vczjk/is7;->OooOOO:Llyiahf/vczjk/fe7;

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string v1, ", code="

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    iget v1, p0, Llyiahf/vczjk/is7;->OooOOOo:I

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    const-string v1, ", message="

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    iget-object v1, p0, Llyiahf/vczjk/is7;->OooOOOO:Ljava/lang/String;

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v1, ", url="

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    iget-object v1, p0, Llyiahf/vczjk/is7;->OooOOO0:Llyiahf/vczjk/lr;

    iget-object v1, v1, Llyiahf/vczjk/lr;->OooOOO:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/lr3;

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const/16 v1, 0x7d

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method
