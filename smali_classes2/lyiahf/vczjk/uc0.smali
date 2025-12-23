.class public final Llyiahf/vczjk/uc0;
.super Llyiahf/vczjk/r02;
.source "SourceFile"


# instance fields
.field public final synthetic OooOOO:Llyiahf/vczjk/oea;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/oea;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/uc0;->OooOOO:Llyiahf/vczjk/oea;

    return-void
.end method


# virtual methods
.method public final OooOoO()V
    .locals 3

    sget-object v0, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    iget-object v1, p0, Llyiahf/vczjk/uc0;->OooOOO:Llyiahf/vczjk/oea;

    const-string v2, "Unknown reason"

    invoke-virtual {v1, v0, v2}, Llyiahf/vczjk/oea;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    return-void
.end method

.method public final OooOoO0(ILjava/lang/CharSequence;)V
    .locals 2

    const-string v0, "errString"

    invoke-static {p2, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    sget-object v0, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    new-instance v1, Ljava/lang/StringBuilder;

    invoke-direct {v1}, Ljava/lang/StringBuilder;-><init>()V

    invoke-virtual {v1, p1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    const-string p1, " - "

    invoke-virtual {v1, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v1, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p1

    iget-object p2, p0, Llyiahf/vczjk/uc0;->OooOOO:Llyiahf/vczjk/oea;

    invoke-virtual {p2, v0, p1}, Llyiahf/vczjk/oea;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    return-void
.end method

.method public final OooOoOO(Llyiahf/vczjk/mc0;)V
    .locals 2

    const-string v0, "result"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    sget-object p1, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    iget-object v0, p0, Llyiahf/vczjk/uc0;->OooOOO:Llyiahf/vczjk/oea;

    const-string v1, "Success"

    invoke-virtual {v0, p1, v1}, Llyiahf/vczjk/oea;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    return-void
.end method
