.class public final Llyiahf/vczjk/g44;
.super Llyiahf/vczjk/qj5;
.source "SourceFile"


# static fields
.field private static final serialVersionUID:J = 0x1L


# instance fields
.field protected final _propertyName:Llyiahf/vczjk/xa7;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/v72;Ljava/lang/String;Llyiahf/vczjk/xa7;)V
    .locals 1

    iget-object p1, p1, Llyiahf/vczjk/v72;->OooOo:Llyiahf/vczjk/eb4;

    const/4 v0, 0x0

    invoke-direct {p0, p1, p2, v0}, Llyiahf/vczjk/qj5;-><init>(Llyiahf/vczjk/eb4;Ljava/lang/String;Llyiahf/vczjk/x64;)V

    iput-object p3, p0, Llyiahf/vczjk/g44;->_propertyName:Llyiahf/vczjk/xa7;

    return-void
.end method

.method public static OooO(Llyiahf/vczjk/v72;Llyiahf/vczjk/xa7;Llyiahf/vczjk/x64;)Llyiahf/vczjk/g44;
    .locals 2

    sget-object v0, Llyiahf/vczjk/vy0;->OooO00o:[Ljava/lang/annotation/Annotation;

    if-nez p1, :cond_0

    const-string v0, "<UNKNOWN>"

    goto :goto_0

    :cond_0
    new-instance v0, Ljava/lang/StringBuilder;

    const-string v1, "\""

    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    :goto_0
    const-string v1, "Invalid `null` value encountered for property "

    invoke-virtual {v1, v0}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v0

    new-instance v1, Llyiahf/vczjk/g44;

    invoke-direct {v1, p0, v0, p1}, Llyiahf/vczjk/g44;-><init>(Llyiahf/vczjk/v72;Ljava/lang/String;Llyiahf/vczjk/xa7;)V

    if-eqz p2, :cond_1

    invoke-virtual {p2}, Llyiahf/vczjk/x64;->OoooO()Ljava/lang/Class;

    move-result-object p0

    iput-object p0, v1, Llyiahf/vczjk/qj5;->_targetType:Ljava/lang/Class;

    :cond_1
    return-object v1
.end method
