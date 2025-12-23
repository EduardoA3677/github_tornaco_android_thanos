.class public abstract Llyiahf/vczjk/en7;
.super Ljava/lang/Object;
.source "SourceFile"


# static fields
.field public static final OooO00o:Llyiahf/vczjk/h72;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    sget-object v0, Llyiahf/vczjk/h72;->OooO0OO:Llyiahf/vczjk/h72;

    sput-object v0, Llyiahf/vczjk/en7;->OooO00o:Llyiahf/vczjk/h72;

    return-void
.end method

.method public static OooO00o(Ljava/lang/StringBuilder;Llyiahf/vczjk/eo0;)V
    .locals 3

    invoke-static {p1}, Llyiahf/vczjk/mba;->OooO0oO(Llyiahf/vczjk/eo0;)Llyiahf/vczjk/mp4;

    move-result-object v0

    invoke-interface {p1}, Llyiahf/vczjk/co0;->Ooooooo()Llyiahf/vczjk/mp4;

    move-result-object p1

    const-string v1, "."

    if-eqz v0, :cond_0

    invoke-virtual {v0}, Llyiahf/vczjk/mp4;->getType()Llyiahf/vczjk/uk4;

    move-result-object v2

    invoke-static {v2}, Llyiahf/vczjk/en7;->OooO0Oo(Llyiahf/vczjk/uk4;)Ljava/lang/String;

    move-result-object v2

    invoke-virtual {p0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {p0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    :cond_0
    if-eqz v0, :cond_1

    if-eqz p1, :cond_1

    const/4 v0, 0x1

    goto :goto_0

    :cond_1
    const/4 v0, 0x0

    :goto_0
    if-eqz v0, :cond_2

    const-string v2, "("

    invoke-virtual {p0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    :cond_2
    if-eqz p1, :cond_3

    invoke-virtual {p1}, Llyiahf/vczjk/mp4;->getType()Llyiahf/vczjk/uk4;

    move-result-object p1

    invoke-static {p1}, Llyiahf/vczjk/en7;->OooO0Oo(Llyiahf/vczjk/uk4;)Ljava/lang/String;

    move-result-object p1

    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {p0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    :cond_3
    if-eqz v0, :cond_4

    const-string p1, ")"

    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    :cond_4
    return-void
.end method

.method public static OooO0O0(Llyiahf/vczjk/rf3;)Ljava/lang/String;
    .locals 8

    const-string v0, "descriptor"

    invoke-static {p0, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v2, Ljava/lang/StringBuilder;

    invoke-direct {v2}, Ljava/lang/StringBuilder;-><init>()V

    const-string v0, "fun "

    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-static {v2, p0}, Llyiahf/vczjk/en7;->OooO00o(Ljava/lang/StringBuilder;Llyiahf/vczjk/eo0;)V

    move-object v0, p0

    check-cast v0, Llyiahf/vczjk/w02;

    invoke-virtual {v0}, Llyiahf/vczjk/w02;->getName()Llyiahf/vczjk/qt5;

    move-result-object v0

    const-string v1, "getName(...)"

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    const/4 v1, 0x1

    sget-object v3, Llyiahf/vczjk/en7;->OooO00o:Llyiahf/vczjk/h72;

    invoke-virtual {v3, v0, v1}, Llyiahf/vczjk/h72;->Oooo0oo(Llyiahf/vczjk/qt5;Z)Ljava/lang/String;

    move-result-object v0

    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-interface {p0}, Llyiahf/vczjk/co0;->OoooOOO()Ljava/util/List;

    move-result-object v1

    const-string v0, "getValueParameters(...)"

    invoke-static {v1, v0}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    sget-object v6, Llyiahf/vczjk/iu6;->OooOo0:Llyiahf/vczjk/iu6;

    const-string v4, "("

    const-string v5, ")"

    const-string v3, ", "

    const/16 v7, 0x30

    invoke-static/range {v1 .. v7}, Llyiahf/vczjk/d21;->o0ooOOo(Ljava/lang/Iterable;Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Llyiahf/vczjk/oe3;I)V

    const-string v0, ": "

    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-interface {p0}, Llyiahf/vczjk/co0;->OooOOoo()Llyiahf/vczjk/uk4;

    move-result-object p0

    invoke-static {p0}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    invoke-static {p0}, Llyiahf/vczjk/en7;->OooO0Oo(Llyiahf/vczjk/uk4;)Ljava/lang/String;

    move-result-object p0

    invoke-virtual {v2, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p0

    return-object p0
.end method

.method public static OooO0OO(Llyiahf/vczjk/sa7;)Ljava/lang/String;
    .locals 4

    const-string v0, "descriptor"

    invoke-static {p0, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v0, Ljava/lang/StringBuilder;

    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    invoke-interface {p0}, Llyiahf/vczjk/ada;->OoooooO()Z

    move-result v1

    if-eqz v1, :cond_0

    const-string v1, "var "

    goto :goto_0

    :cond_0
    const-string v1, "val "

    :goto_0
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-static {v0, p0}, Llyiahf/vczjk/en7;->OooO00o(Ljava/lang/StringBuilder;Llyiahf/vczjk/eo0;)V

    invoke-interface {p0}, Llyiahf/vczjk/v02;->getName()Llyiahf/vczjk/qt5;

    move-result-object v1

    const-string v2, "getName(...)"

    invoke-static {v1, v2}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    const/4 v2, 0x1

    sget-object v3, Llyiahf/vczjk/en7;->OooO00o:Llyiahf/vczjk/h72;

    invoke-virtual {v3, v1, v2}, Llyiahf/vczjk/h72;->Oooo0oo(Llyiahf/vczjk/qt5;Z)Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v1, ": "

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-interface {p0}, Llyiahf/vczjk/gca;->getType()Llyiahf/vczjk/uk4;

    move-result-object p0

    const-string v1, "getType(...)"

    invoke-static {p0, v1}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {p0}, Llyiahf/vczjk/en7;->OooO0Oo(Llyiahf/vczjk/uk4;)Ljava/lang/String;

    move-result-object p0

    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p0

    return-object p0
.end method

.method public static OooO0Oo(Llyiahf/vczjk/uk4;)Ljava/lang/String;
    .locals 1

    const-string v0, "type"

    invoke-static {p0, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    sget-object v0, Llyiahf/vczjk/en7;->OooO00o:Llyiahf/vczjk/h72;

    invoke-virtual {v0, p0}, Llyiahf/vczjk/h72;->OoooOOo(Llyiahf/vczjk/uk4;)Ljava/lang/String;

    move-result-object p0

    return-object p0
.end method
