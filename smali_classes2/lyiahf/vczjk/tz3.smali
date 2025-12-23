.class public final Llyiahf/vczjk/tz3;
.super Llyiahf/vczjk/fca;
.source "SourceFile"


# instance fields
.field public final OooO00o:Llyiahf/vczjk/qt5;

.field public final OooO0O0:Llyiahf/vczjk/pt7;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/qt5;Llyiahf/vczjk/pt7;)V
    .locals 1

    const-string v0, "underlyingType"

    invoke-static {p2, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/tz3;->OooO00o:Llyiahf/vczjk/qt5;

    iput-object p2, p0, Llyiahf/vczjk/tz3;->OooO0O0:Llyiahf/vczjk/pt7;

    return-void
.end method


# virtual methods
.method public final OooO00o(Llyiahf/vczjk/qt5;)Z
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/tz3;->OooO00o:Llyiahf/vczjk/qt5;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/qt5;->equals(Ljava/lang/Object;)Z

    move-result p1

    return p1
.end method

.method public final toString()Ljava/lang/String;
    .locals 2

    new-instance v0, Ljava/lang/StringBuilder;

    const-string v1, "InlineClassRepresentation(underlyingPropertyName="

    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    iget-object v1, p0, Llyiahf/vczjk/tz3;->OooO00o:Llyiahf/vczjk/qt5;

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string v1, ", underlyingType="

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    iget-object v1, p0, Llyiahf/vczjk/tz3;->OooO0O0:Llyiahf/vczjk/pt7;

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const/16 v1, 0x29

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method
