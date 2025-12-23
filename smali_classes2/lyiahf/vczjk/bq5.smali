.class public final Llyiahf/vczjk/bq5;
.super Llyiahf/vczjk/fca;
.source "SourceFile"


# instance fields
.field public final OooO00o:Ljava/util/ArrayList;

.field public final OooO0O0:Ljava/util/Map;


# direct methods
.method public constructor <init>(Ljava/util/ArrayList;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/bq5;->OooO00o:Ljava/util/ArrayList;

    invoke-static {p1}, Llyiahf/vczjk/lc5;->o0OOO0o(Ljava/util/List;)Ljava/util/Map;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/bq5;->OooO0O0:Ljava/util/Map;

    return-void
.end method


# virtual methods
.method public final OooO00o(Llyiahf/vczjk/qt5;)Z
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/bq5;->OooO0O0:Ljava/util/Map;

    invoke-interface {v0, p1}, Ljava/util/Map;->containsKey(Ljava/lang/Object;)Z

    move-result p1

    return p1
.end method

.method public final toString()Ljava/lang/String;
    .locals 2

    new-instance v0, Ljava/lang/StringBuilder;

    const-string v1, "MultiFieldValueClassRepresentation(underlyingPropertyNamesToTypes="

    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    iget-object v1, p0, Llyiahf/vczjk/bq5;->OooO00o:Ljava/util/ArrayList;

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const/16 v1, 0x29

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method
