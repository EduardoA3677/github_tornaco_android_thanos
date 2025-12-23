.class public final Llyiahf/vczjk/zta;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $compressedSize:Llyiahf/vczjk/gl7;

.field final synthetic $hasZip64Extra:Llyiahf/vczjk/dl7;

.field final synthetic $ntfsCreatedAtFiletime:Llyiahf/vczjk/hl7;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/hl7;"
        }
    .end annotation
.end field

.field final synthetic $ntfsLastAccessedAtFiletime:Llyiahf/vczjk/hl7;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/hl7;"
        }
    .end annotation
.end field

.field final synthetic $ntfsLastModifiedAtFiletime:Llyiahf/vczjk/hl7;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/hl7;"
        }
    .end annotation
.end field

.field final synthetic $offset:Llyiahf/vczjk/gl7;

.field final synthetic $requiredZip64ExtraSize:J

.field final synthetic $size:Llyiahf/vczjk/gl7;

.field final synthetic $this_readCentralDirectoryZipEntry:Llyiahf/vczjk/nj0;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/dl7;JLlyiahf/vczjk/gl7;Llyiahf/vczjk/ih7;Llyiahf/vczjk/gl7;Llyiahf/vczjk/gl7;Llyiahf/vczjk/hl7;Llyiahf/vczjk/hl7;Llyiahf/vczjk/hl7;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/zta;->$hasZip64Extra:Llyiahf/vczjk/dl7;

    iput-wide p2, p0, Llyiahf/vczjk/zta;->$requiredZip64ExtraSize:J

    iput-object p4, p0, Llyiahf/vczjk/zta;->$size:Llyiahf/vczjk/gl7;

    iput-object p5, p0, Llyiahf/vczjk/zta;->$this_readCentralDirectoryZipEntry:Llyiahf/vczjk/nj0;

    iput-object p6, p0, Llyiahf/vczjk/zta;->$compressedSize:Llyiahf/vczjk/gl7;

    iput-object p7, p0, Llyiahf/vczjk/zta;->$offset:Llyiahf/vczjk/gl7;

    iput-object p8, p0, Llyiahf/vczjk/zta;->$ntfsLastModifiedAtFiletime:Llyiahf/vczjk/hl7;

    iput-object p9, p0, Llyiahf/vczjk/zta;->$ntfsLastAccessedAtFiletime:Llyiahf/vczjk/hl7;

    iput-object p10, p0, Llyiahf/vczjk/zta;->$ntfsCreatedAtFiletime:Llyiahf/vczjk/hl7;

    const/4 p1, 0x2

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 6

    check-cast p1, Ljava/lang/Number;

    invoke-virtual {p1}, Ljava/lang/Number;->intValue()I

    move-result p1

    check-cast p2, Ljava/lang/Number;

    invoke-virtual {p2}, Ljava/lang/Number;->longValue()J

    move-result-wide v0

    const/4 p2, 0x1

    if-eq p1, p2, :cond_2

    const/16 p2, 0xa

    if-eq p1, p2, :cond_0

    goto :goto_1

    :cond_0
    const-wide/16 p1, 0x4

    cmp-long v2, v0, p1

    if-ltz v2, :cond_1

    iget-object v2, p0, Llyiahf/vczjk/zta;->$this_readCentralDirectoryZipEntry:Llyiahf/vczjk/nj0;

    invoke-interface {v2, p1, p2}, Llyiahf/vczjk/nj0;->skip(J)V

    iget-object v2, p0, Llyiahf/vczjk/zta;->$this_readCentralDirectoryZipEntry:Llyiahf/vczjk/nj0;

    sub-long/2addr v0, p1

    long-to-int p1, v0

    new-instance p2, Llyiahf/vczjk/yta;

    iget-object v0, p0, Llyiahf/vczjk/zta;->$ntfsLastModifiedAtFiletime:Llyiahf/vczjk/hl7;

    iget-object v1, p0, Llyiahf/vczjk/zta;->$ntfsLastAccessedAtFiletime:Llyiahf/vczjk/hl7;

    iget-object v3, p0, Llyiahf/vczjk/zta;->$ntfsCreatedAtFiletime:Llyiahf/vczjk/hl7;

    invoke-direct {p2, v0, v2, v1, v3}, Llyiahf/vczjk/yta;-><init>(Llyiahf/vczjk/hl7;Llyiahf/vczjk/nj0;Llyiahf/vczjk/hl7;Llyiahf/vczjk/hl7;)V

    invoke-static {v2, p1, p2}, Llyiahf/vczjk/ht6;->OooOo0(Llyiahf/vczjk/nj0;ILlyiahf/vczjk/ze3;)V

    goto :goto_1

    :cond_1
    new-instance p1, Ljava/io/IOException;

    const-string p2, "bad zip: NTFS extra too short"

    invoke-direct {p1, p2}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_2
    iget-object p1, p0, Llyiahf/vczjk/zta;->$hasZip64Extra:Llyiahf/vczjk/dl7;

    iget-boolean v2, p1, Llyiahf/vczjk/dl7;->element:Z

    if-nez v2, :cond_7

    iput-boolean p2, p1, Llyiahf/vczjk/dl7;->element:Z

    iget-wide p1, p0, Llyiahf/vczjk/zta;->$requiredZip64ExtraSize:J

    cmp-long p1, v0, p1

    if-ltz p1, :cond_6

    iget-object p1, p0, Llyiahf/vczjk/zta;->$size:Llyiahf/vczjk/gl7;

    iget-wide v0, p1, Llyiahf/vczjk/gl7;->element:J

    const-wide v2, 0xffffffffL

    cmp-long p2, v0, v2

    if-nez p2, :cond_3

    iget-object p2, p0, Llyiahf/vczjk/zta;->$this_readCentralDirectoryZipEntry:Llyiahf/vczjk/nj0;

    invoke-interface {p2}, Llyiahf/vczjk/nj0;->o0ooOoO()J

    move-result-wide v0

    :cond_3
    iput-wide v0, p1, Llyiahf/vczjk/gl7;->element:J

    iget-object p1, p0, Llyiahf/vczjk/zta;->$compressedSize:Llyiahf/vczjk/gl7;

    iget-wide v0, p1, Llyiahf/vczjk/gl7;->element:J

    cmp-long p2, v0, v2

    const-wide/16 v0, 0x0

    if-nez p2, :cond_4

    iget-object p2, p0, Llyiahf/vczjk/zta;->$this_readCentralDirectoryZipEntry:Llyiahf/vczjk/nj0;

    invoke-interface {p2}, Llyiahf/vczjk/nj0;->o0ooOoO()J

    move-result-wide v4

    goto :goto_0

    :cond_4
    move-wide v4, v0

    :goto_0
    iput-wide v4, p1, Llyiahf/vczjk/gl7;->element:J

    iget-object p1, p0, Llyiahf/vczjk/zta;->$offset:Llyiahf/vczjk/gl7;

    iget-wide v4, p1, Llyiahf/vczjk/gl7;->element:J

    cmp-long p2, v4, v2

    if-nez p2, :cond_5

    iget-object p2, p0, Llyiahf/vczjk/zta;->$this_readCentralDirectoryZipEntry:Llyiahf/vczjk/nj0;

    invoke-interface {p2}, Llyiahf/vczjk/nj0;->o0ooOoO()J

    move-result-wide v0

    :cond_5
    iput-wide v0, p1, Llyiahf/vczjk/gl7;->element:J

    :goto_1
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :cond_6
    new-instance p1, Ljava/io/IOException;

    const-string p2, "bad zip: zip64 extra too short"

    invoke-direct {p1, p2}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_7
    new-instance p1, Ljava/io/IOException;

    const-string p2, "bad zip: zip64 extra repeated"

    invoke-direct {p1, p2}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    throw p1
.end method
