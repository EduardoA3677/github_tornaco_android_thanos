.class public final Llyiahf/vczjk/br5;
.super Llyiahf/vczjk/cr7;
.source "SourceFile"


# static fields
.field public static final OooO:[B

.field public static final OooO0o:Llyiahf/vczjk/uf5;

.field public static final OooO0o0:Llyiahf/vczjk/uf5;

.field public static final OooO0oO:[B

.field public static final OooO0oo:[B


# instance fields
.field public final OooO00o:Llyiahf/vczjk/jm0;

.field public final OooO0O0:Ljava/util/List;

.field public final OooO0OO:Llyiahf/vczjk/uf5;

.field public OooO0Oo:J


# direct methods
.method static constructor <clinit>()V
    .locals 2

    const/4 v0, 0x2

    sget-object v1, Llyiahf/vczjk/uf5;->OooO0Oo:Ljava/util/regex/Pattern;

    const-string v1, "multipart/mixed"

    invoke-static {v1}, Llyiahf/vczjk/zsa;->OoooO00(Ljava/lang/String;)Llyiahf/vczjk/uf5;

    move-result-object v1

    sput-object v1, Llyiahf/vczjk/br5;->OooO0o0:Llyiahf/vczjk/uf5;

    const-string v1, "multipart/alternative"

    invoke-static {v1}, Llyiahf/vczjk/zsa;->OoooO00(Ljava/lang/String;)Llyiahf/vczjk/uf5;

    const-string v1, "multipart/digest"

    invoke-static {v1}, Llyiahf/vczjk/zsa;->OoooO00(Ljava/lang/String;)Llyiahf/vczjk/uf5;

    const-string v1, "multipart/parallel"

    invoke-static {v1}, Llyiahf/vczjk/zsa;->OoooO00(Ljava/lang/String;)Llyiahf/vczjk/uf5;

    const-string v1, "multipart/form-data"

    invoke-static {v1}, Llyiahf/vczjk/zsa;->OoooO00(Ljava/lang/String;)Llyiahf/vczjk/uf5;

    move-result-object v1

    sput-object v1, Llyiahf/vczjk/br5;->OooO0o:Llyiahf/vczjk/uf5;

    new-array v1, v0, [B

    fill-array-data v1, :array_0

    sput-object v1, Llyiahf/vczjk/br5;->OooO0oO:[B

    new-array v1, v0, [B

    fill-array-data v1, :array_1

    sput-object v1, Llyiahf/vczjk/br5;->OooO0oo:[B

    new-array v0, v0, [B

    fill-array-data v0, :array_2

    sput-object v0, Llyiahf/vczjk/br5;->OooO:[B

    return-void

    :array_0
    .array-data 1
        0x3at
        0x20t
    .end array-data

    nop

    :array_1
    .array-data 1
        0xdt
        0xat
    .end array-data

    nop

    :array_2
    .array-data 1
        0x2dt
        0x2dt
    .end array-data
.end method

.method public constructor <init>(Llyiahf/vczjk/jm0;Llyiahf/vczjk/uf5;Ljava/util/List;)V
    .locals 1

    const-string v0, "boundaryByteString"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "type"

    invoke-static {p2, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/br5;->OooO00o:Llyiahf/vczjk/jm0;

    iput-object p3, p0, Llyiahf/vczjk/br5;->OooO0O0:Ljava/util/List;

    sget-object p3, Llyiahf/vczjk/uf5;->OooO0Oo:Ljava/util/regex/Pattern;

    new-instance p3, Ljava/lang/StringBuilder;

    invoke-direct {p3}, Ljava/lang/StringBuilder;-><init>()V

    invoke-virtual {p3, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string p2, "; boundary="

    invoke-virtual {p3, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {p1}, Llyiahf/vczjk/jm0;->OooOOoo()Ljava/lang/String;

    move-result-object p1

    invoke-virtual {p3, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {p3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p1

    invoke-static {p1}, Llyiahf/vczjk/zsa;->OoooO00(Ljava/lang/String;)Llyiahf/vczjk/uf5;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/br5;->OooO0OO:Llyiahf/vczjk/uf5;

    const-wide/16 p1, -0x1

    iput-wide p1, p0, Llyiahf/vczjk/br5;->OooO0Oo:J

    return-void
.end method


# virtual methods
.method public final OooO00o()J
    .locals 4

    iget-wide v0, p0, Llyiahf/vczjk/br5;->OooO0Oo:J

    const-wide/16 v2, -0x1

    cmp-long v2, v0, v2

    if-nez v2, :cond_0

    const/4 v0, 0x0

    const/4 v1, 0x1

    invoke-virtual {p0, v0, v1}, Llyiahf/vczjk/br5;->OooO0Oo(Llyiahf/vczjk/mj0;Z)J

    move-result-wide v0

    iput-wide v0, p0, Llyiahf/vczjk/br5;->OooO0Oo:J

    :cond_0
    return-wide v0
.end method

.method public final OooO0O0()Llyiahf/vczjk/uf5;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/br5;->OooO0OO:Llyiahf/vczjk/uf5;

    return-object v0
.end method

.method public final OooO0OO(Llyiahf/vczjk/mj0;)V
    .locals 1

    const/4 v0, 0x0

    invoke-virtual {p0, p1, v0}, Llyiahf/vczjk/br5;->OooO0Oo(Llyiahf/vczjk/mj0;Z)J

    return-void
.end method

.method public final OooO0Oo(Llyiahf/vczjk/mj0;Z)J
    .locals 16

    move-object/from16 v0, p0

    if-eqz p2, :cond_0

    new-instance v1, Llyiahf/vczjk/yi0;

    invoke-direct {v1}, Ljava/lang/Object;-><init>()V

    move-object v2, v1

    goto :goto_0

    :cond_0
    const/4 v1, 0x0

    move-object v2, v1

    move-object/from16 v1, p1

    :goto_0
    iget-object v3, v0, Llyiahf/vczjk/br5;->OooO0O0:Ljava/util/List;

    invoke-interface {v3}, Ljava/util/List;->size()I

    move-result v4

    const/4 v5, 0x0

    const-wide/16 v6, 0x0

    move v8, v5

    :goto_1
    iget-object v9, v0, Llyiahf/vczjk/br5;->OooO00o:Llyiahf/vczjk/jm0;

    sget-object v10, Llyiahf/vczjk/br5;->OooO:[B

    sget-object v11, Llyiahf/vczjk/br5;->OooO0oo:[B

    if-ge v8, v4, :cond_6

    invoke-interface {v3, v8}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v12

    check-cast v12, Llyiahf/vczjk/ar5;

    iget-object v13, v12, Llyiahf/vczjk/ar5;->OooO00o:Llyiahf/vczjk/vm3;

    invoke-static {v1}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    invoke-interface {v1, v10}, Llyiahf/vczjk/mj0;->write([B)Llyiahf/vczjk/mj0;

    invoke-interface {v1, v9}, Llyiahf/vczjk/mj0;->OooOo0(Llyiahf/vczjk/jm0;)Llyiahf/vczjk/mj0;

    invoke-interface {v1, v11}, Llyiahf/vczjk/mj0;->write([B)Llyiahf/vczjk/mj0;

    invoke-virtual {v13}, Llyiahf/vczjk/vm3;->size()I

    move-result v9

    move v10, v5

    :goto_2
    if-ge v10, v9, :cond_1

    invoke-virtual {v13, v10}, Llyiahf/vczjk/vm3;->OooO0O0(I)Ljava/lang/String;

    move-result-object v14

    invoke-interface {v1, v14}, Llyiahf/vczjk/mj0;->o000oOoO(Ljava/lang/String;)Llyiahf/vczjk/mj0;

    move-result-object v14

    sget-object v15, Llyiahf/vczjk/br5;->OooO0oO:[B

    invoke-interface {v14, v15}, Llyiahf/vczjk/mj0;->write([B)Llyiahf/vczjk/mj0;

    move-result-object v14

    invoke-virtual {v13, v10}, Llyiahf/vczjk/vm3;->OooO0oo(I)Ljava/lang/String;

    move-result-object v15

    invoke-interface {v14, v15}, Llyiahf/vczjk/mj0;->o000oOoO(Ljava/lang/String;)Llyiahf/vczjk/mj0;

    move-result-object v14

    invoke-interface {v14, v11}, Llyiahf/vczjk/mj0;->write([B)Llyiahf/vczjk/mj0;

    add-int/lit8 v10, v10, 0x1

    goto :goto_2

    :cond_1
    iget-object v9, v12, Llyiahf/vczjk/ar5;->OooO0O0:Llyiahf/vczjk/cr7;

    invoke-virtual {v9}, Llyiahf/vczjk/cr7;->OooO0O0()Llyiahf/vczjk/uf5;

    move-result-object v10

    if-eqz v10, :cond_2

    const-string v12, "Content-Type: "

    invoke-interface {v1, v12}, Llyiahf/vczjk/mj0;->o000oOoO(Ljava/lang/String;)Llyiahf/vczjk/mj0;

    move-result-object v12

    iget-object v10, v10, Llyiahf/vczjk/uf5;->OooO00o:Ljava/lang/String;

    invoke-interface {v12, v10}, Llyiahf/vczjk/mj0;->o000oOoO(Ljava/lang/String;)Llyiahf/vczjk/mj0;

    move-result-object v10

    invoke-interface {v10, v11}, Llyiahf/vczjk/mj0;->write([B)Llyiahf/vczjk/mj0;

    :cond_2
    invoke-virtual {v9}, Llyiahf/vczjk/cr7;->OooO00o()J

    move-result-wide v12

    const-wide/16 v14, -0x1

    cmp-long v10, v12, v14

    if-eqz v10, :cond_3

    const-string v10, "Content-Length: "

    invoke-interface {v1, v10}, Llyiahf/vczjk/mj0;->o000oOoO(Ljava/lang/String;)Llyiahf/vczjk/mj0;

    move-result-object v10

    invoke-interface {v10, v12, v13}, Llyiahf/vczjk/mj0;->o00000(J)Llyiahf/vczjk/mj0;

    move-result-object v10

    invoke-interface {v10, v11}, Llyiahf/vczjk/mj0;->write([B)Llyiahf/vczjk/mj0;

    goto :goto_3

    :cond_3
    if-eqz p2, :cond_4

    invoke-static {v2}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    invoke-virtual {v2}, Llyiahf/vczjk/yi0;->OooO0Oo()V

    return-wide v14

    :cond_4
    :goto_3
    invoke-interface {v1, v11}, Llyiahf/vczjk/mj0;->write([B)Llyiahf/vczjk/mj0;

    if-eqz p2, :cond_5

    add-long/2addr v6, v12

    goto :goto_4

    :cond_5
    invoke-virtual {v9, v1}, Llyiahf/vczjk/cr7;->OooO0OO(Llyiahf/vczjk/mj0;)V

    :goto_4
    invoke-interface {v1, v11}, Llyiahf/vczjk/mj0;->write([B)Llyiahf/vczjk/mj0;

    add-int/lit8 v8, v8, 0x1

    goto/16 :goto_1

    :cond_6
    invoke-static {v1}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    invoke-interface {v1, v10}, Llyiahf/vczjk/mj0;->write([B)Llyiahf/vczjk/mj0;

    invoke-interface {v1, v9}, Llyiahf/vczjk/mj0;->OooOo0(Llyiahf/vczjk/jm0;)Llyiahf/vczjk/mj0;

    invoke-interface {v1, v10}, Llyiahf/vczjk/mj0;->write([B)Llyiahf/vczjk/mj0;

    invoke-interface {v1, v11}, Llyiahf/vczjk/mj0;->write([B)Llyiahf/vczjk/mj0;

    if-eqz p2, :cond_7

    invoke-static {v2}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    iget-wide v3, v2, Llyiahf/vczjk/yi0;->OooOOO:J

    add-long/2addr v6, v3

    invoke-virtual {v2}, Llyiahf/vczjk/yi0;->OooO0Oo()V

    :cond_7
    return-wide v6
.end method
