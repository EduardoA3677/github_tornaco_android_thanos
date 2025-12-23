.class public final Llyiahf/vczjk/br3;
.super Ljava/lang/RuntimeException;
.source "SourceFile"


# instance fields
.field private final response:Llyiahf/vczjk/is7;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/is7;)V
    .locals 2

    new-instance v0, Ljava/lang/StringBuilder;

    const-string v1, "HTTP "

    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    iget v1, p1, Llyiahf/vczjk/is7;->OooOOOo:I

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    const-string v1, ": "

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    iget-object v1, p1, Llyiahf/vczjk/is7;->OooOOOO:Ljava/lang/String;

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    invoke-direct {p0, v0}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;)V

    iput-object p1, p0, Llyiahf/vczjk/br3;->response:Llyiahf/vczjk/is7;

    return-void
.end method
