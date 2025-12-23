.class public Llyiahf/vczjk/zq3;
.super Ljava/lang/RuntimeException;
.source "SourceFile"


# instance fields
.field private final code:I

.field private final message:Ljava/lang/String;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/hs7;)V
    .locals 2

    const-string v0, "response == null"

    invoke-static {p1, v0}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/Object;

    new-instance v0, Ljava/lang/StringBuilder;

    const-string v1, "HTTP "

    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    iget-object p1, p1, Llyiahf/vczjk/hs7;->OooO00o:Llyiahf/vczjk/is7;

    iget v1, p1, Llyiahf/vczjk/is7;->OooOOOo:I

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    const-string v1, " "

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    iget-object v1, p1, Llyiahf/vczjk/is7;->OooOOOO:Ljava/lang/String;

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    invoke-direct {p0, v0}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;)V

    iget v0, p1, Llyiahf/vczjk/is7;->OooOOOo:I

    iput v0, p0, Llyiahf/vczjk/zq3;->code:I

    iget-object p1, p1, Llyiahf/vczjk/is7;->OooOOOO:Ljava/lang/String;

    iput-object p1, p0, Llyiahf/vczjk/zq3;->message:Ljava/lang/String;

    return-void
.end method
