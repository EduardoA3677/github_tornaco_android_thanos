.class public final Llyiahf/vczjk/yta;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
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

.field final synthetic $this_readCentralDirectoryZipEntry:Llyiahf/vczjk/nj0;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/hl7;Llyiahf/vczjk/nj0;Llyiahf/vczjk/hl7;Llyiahf/vczjk/hl7;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/yta;->$ntfsLastModifiedAtFiletime:Llyiahf/vczjk/hl7;

    iput-object p2, p0, Llyiahf/vczjk/yta;->$this_readCentralDirectoryZipEntry:Llyiahf/vczjk/nj0;

    iput-object p3, p0, Llyiahf/vczjk/yta;->$ntfsLastAccessedAtFiletime:Llyiahf/vczjk/hl7;

    iput-object p4, p0, Llyiahf/vczjk/yta;->$ntfsCreatedAtFiletime:Llyiahf/vczjk/hl7;

    const/4 p1, 0x2

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 4

    check-cast p1, Ljava/lang/Number;

    invoke-virtual {p1}, Ljava/lang/Number;->intValue()I

    move-result p1

    check-cast p2, Ljava/lang/Number;

    invoke-virtual {p2}, Ljava/lang/Number;->longValue()J

    move-result-wide v0

    const/4 p2, 0x1

    if-ne p1, p2, :cond_2

    iget-object p1, p0, Llyiahf/vczjk/yta;->$ntfsLastModifiedAtFiletime:Llyiahf/vczjk/hl7;

    iget-object p2, p1, Llyiahf/vczjk/hl7;->element:Ljava/lang/Object;

    if-nez p2, :cond_1

    const-wide/16 v2, 0x18

    cmp-long p2, v0, v2

    if-nez p2, :cond_0

    iget-object p2, p0, Llyiahf/vczjk/yta;->$this_readCentralDirectoryZipEntry:Llyiahf/vczjk/nj0;

    invoke-interface {p2}, Llyiahf/vczjk/nj0;->o0ooOoO()J

    move-result-wide v0

    invoke-static {v0, v1}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    move-result-object p2

    iput-object p2, p1, Llyiahf/vczjk/hl7;->element:Ljava/lang/Object;

    iget-object p1, p0, Llyiahf/vczjk/yta;->$ntfsLastAccessedAtFiletime:Llyiahf/vczjk/hl7;

    iget-object p2, p0, Llyiahf/vczjk/yta;->$this_readCentralDirectoryZipEntry:Llyiahf/vczjk/nj0;

    invoke-interface {p2}, Llyiahf/vczjk/nj0;->o0ooOoO()J

    move-result-wide v0

    invoke-static {v0, v1}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    move-result-object p2

    iput-object p2, p1, Llyiahf/vczjk/hl7;->element:Ljava/lang/Object;

    iget-object p1, p0, Llyiahf/vczjk/yta;->$ntfsCreatedAtFiletime:Llyiahf/vczjk/hl7;

    iget-object p2, p0, Llyiahf/vczjk/yta;->$this_readCentralDirectoryZipEntry:Llyiahf/vczjk/nj0;

    invoke-interface {p2}, Llyiahf/vczjk/nj0;->o0ooOoO()J

    move-result-wide v0

    invoke-static {v0, v1}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    move-result-object p2

    iput-object p2, p1, Llyiahf/vczjk/hl7;->element:Ljava/lang/Object;

    goto :goto_0

    :cond_0
    new-instance p1, Ljava/io/IOException;

    const-string p2, "bad zip: NTFS extra attribute tag 0x0001 size != 24"

    invoke-direct {p1, p2}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_1
    new-instance p1, Ljava/io/IOException;

    const-string p2, "bad zip: NTFS extra attribute tag 0x0001 repeated"

    invoke-direct {p1, p2}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_2
    :goto_0
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
