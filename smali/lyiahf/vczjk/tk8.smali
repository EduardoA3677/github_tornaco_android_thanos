.class public final Llyiahf/vczjk/tk8;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/an1;


# instance fields
.field public final OooO00o:I

.field public final OooO0O0:Llyiahf/vczjk/ii;

.field public final OooO0OO:Llyiahf/vczjk/ii;

.field public final OooO0Oo:Llyiahf/vczjk/ii;

.field public final OooO0o0:Z


# direct methods
.method public constructor <init>(Ljava/lang/String;ILlyiahf/vczjk/ii;Llyiahf/vczjk/ii;Llyiahf/vczjk/ii;Z)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput p2, p0, Llyiahf/vczjk/tk8;->OooO00o:I

    iput-object p3, p0, Llyiahf/vczjk/tk8;->OooO0O0:Llyiahf/vczjk/ii;

    iput-object p4, p0, Llyiahf/vczjk/tk8;->OooO0OO:Llyiahf/vczjk/ii;

    iput-object p5, p0, Llyiahf/vczjk/tk8;->OooO0Oo:Llyiahf/vczjk/ii;

    iput-boolean p6, p0, Llyiahf/vczjk/tk8;->OooO0o0:Z

    return-void
.end method


# virtual methods
.method public final OooO00o(Llyiahf/vczjk/v85;Llyiahf/vczjk/z75;Llyiahf/vczjk/f80;)Llyiahf/vczjk/fm1;
    .locals 0

    new-instance p1, Llyiahf/vczjk/c1a;

    invoke-direct {p1, p3, p0}, Llyiahf/vczjk/c1a;-><init>(Llyiahf/vczjk/f80;Llyiahf/vczjk/tk8;)V

    return-object p1
.end method

.method public final toString()Ljava/lang/String;
    .locals 2

    new-instance v0, Ljava/lang/StringBuilder;

    const-string v1, "Trim Path: {start: "

    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    iget-object v1, p0, Llyiahf/vczjk/tk8;->OooO0O0:Llyiahf/vczjk/ii;

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string v1, ", end: "

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    iget-object v1, p0, Llyiahf/vczjk/tk8;->OooO0OO:Llyiahf/vczjk/ii;

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string v1, ", offset: "

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    iget-object v1, p0, Llyiahf/vczjk/tk8;->OooO0Oo:Llyiahf/vczjk/ii;

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string v1, "}"

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method
