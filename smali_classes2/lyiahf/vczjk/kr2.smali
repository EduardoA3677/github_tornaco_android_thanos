.class public final Llyiahf/vczjk/kr2;
.super Llyiahf/vczjk/mr2;
.source "SourceFile"


# instance fields
.field public final OooOOOO:Llyiahf/vczjk/yp0;

.field public final synthetic OooOOOo:Llyiahf/vczjk/or2;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/or2;JLlyiahf/vczjk/yp0;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/kr2;->OooOOOo:Llyiahf/vczjk/or2;

    invoke-direct {p0, p2, p3}, Llyiahf/vczjk/mr2;-><init>(J)V

    iput-object p4, p0, Llyiahf/vczjk/kr2;->OooOOOO:Llyiahf/vczjk/yp0;

    return-void
.end method


# virtual methods
.method public final run()V
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/kr2;->OooOOOO:Llyiahf/vczjk/yp0;

    iget-object v1, p0, Llyiahf/vczjk/kr2;->OooOOOo:Llyiahf/vczjk/or2;

    invoke-virtual {v0, v1}, Llyiahf/vczjk/yp0;->OooOooO(Llyiahf/vczjk/qr1;)V

    return-void
.end method

.method public final toString()Ljava/lang/String;
    .locals 2

    new-instance v0, Ljava/lang/StringBuilder;

    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    invoke-super {p0}, Llyiahf/vczjk/mr2;->toString()Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    iget-object v1, p0, Llyiahf/vczjk/kr2;->OooOOOO:Llyiahf/vczjk/yp0;

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method
