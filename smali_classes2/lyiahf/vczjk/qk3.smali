.class public final Llyiahf/vczjk/qk3;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/fp1;


# static fields
.field public static final OooOOOO:Llyiahf/vczjk/uf5;


# instance fields
.field public final OooOOO:Llyiahf/vczjk/r1a;

.field public final OooOOO0:Llyiahf/vczjk/nk3;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    sget-object v0, Llyiahf/vczjk/uf5;->OooO0Oo:Ljava/util/regex/Pattern;

    const-string v0, "application/json; charset=UTF-8"

    invoke-static {v0}, Llyiahf/vczjk/zsa;->OoooO00(Ljava/lang/String;)Llyiahf/vczjk/uf5;

    move-result-object v0

    sput-object v0, Llyiahf/vczjk/qk3;->OooOOOO:Llyiahf/vczjk/uf5;

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/nk3;Llyiahf/vczjk/r1a;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/qk3;->OooOOO0:Llyiahf/vczjk/nk3;

    iput-object p2, p0, Llyiahf/vczjk/qk3;->OooOOO:Llyiahf/vczjk/r1a;

    return-void
.end method


# virtual methods
.method public final convert(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 4

    new-instance v0, Llyiahf/vczjk/yi0;

    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    new-instance v1, Ljava/io/OutputStreamWriter;

    new-instance v2, Llyiahf/vczjk/xi0;

    const/4 v3, 0x0

    invoke-direct {v2, v0, v3}, Llyiahf/vczjk/xi0;-><init>(Llyiahf/vczjk/mj0;I)V

    sget-object v3, Ljava/nio/charset/StandardCharsets;->UTF_8:Ljava/nio/charset/Charset;

    invoke-direct {v1, v2, v3}, Ljava/io/OutputStreamWriter;-><init>(Ljava/io/OutputStream;Ljava/nio/charset/Charset;)V

    iget-object v2, p0, Llyiahf/vczjk/qk3;->OooOOO0:Llyiahf/vczjk/nk3;

    invoke-virtual {v2, v1}, Llyiahf/vczjk/nk3;->OooO0oO(Ljava/io/Writer;)Llyiahf/vczjk/zc4;

    move-result-object v1

    iget-object v2, p0, Llyiahf/vczjk/qk3;->OooOOO:Llyiahf/vczjk/r1a;

    invoke-virtual {v2, v1, p1}, Llyiahf/vczjk/r1a;->OooO0OO(Llyiahf/vczjk/zc4;Ljava/lang/Object;)V

    invoke-virtual {v1}, Llyiahf/vczjk/zc4;->close()V

    iget-wide v1, v0, Llyiahf/vczjk/yi0;->OooOOO:J

    invoke-virtual {v0, v1, v2}, Llyiahf/vczjk/yi0;->OoooOoo(J)Llyiahf/vczjk/jm0;

    move-result-object p1

    const-string v0, "content"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v0, Llyiahf/vczjk/ar7;

    sget-object v1, Llyiahf/vczjk/qk3;->OooOOOO:Llyiahf/vczjk/uf5;

    invoke-direct {v0, v1, p1}, Llyiahf/vczjk/ar7;-><init>(Llyiahf/vczjk/uf5;Llyiahf/vczjk/jm0;)V

    return-object v0
.end method
