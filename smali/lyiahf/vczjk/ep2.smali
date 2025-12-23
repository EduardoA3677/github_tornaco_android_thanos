.class public abstract Llyiahf/vczjk/ep2;
.super Ljava/lang/Object;
.source "SourceFile"


# static fields
.field public static final OooO00o:Llyiahf/vczjk/fp2;


# direct methods
.method static constructor <clinit>()V
    .locals 8

    new-instance v0, Llyiahf/vczjk/fp2;

    new-instance v1, Llyiahf/vczjk/fz9;

    const/4 v5, 0x0

    const/4 v6, 0x0

    const/4 v2, 0x0

    const/4 v3, 0x0

    const/4 v4, 0x0

    const/16 v7, 0x3f

    invoke-direct/range {v1 .. v7}, Llyiahf/vczjk/fz9;-><init>(Llyiahf/vczjk/iv2;Llyiahf/vczjk/hr8;Llyiahf/vczjk/ls0;Llyiahf/vczjk/s78;Ljava/util/LinkedHashMap;I)V

    invoke-direct {v0, v1}, Llyiahf/vczjk/fp2;-><init>(Llyiahf/vczjk/fz9;)V

    sput-object v0, Llyiahf/vczjk/ep2;->OooO00o:Llyiahf/vczjk/fp2;

    return-void
.end method


# virtual methods
.method public final OooO00o(Llyiahf/vczjk/ep2;)Llyiahf/vczjk/fp2;
    .locals 8

    new-instance v0, Llyiahf/vczjk/fp2;

    new-instance v1, Llyiahf/vczjk/fz9;

    check-cast p1, Llyiahf/vczjk/fp2;

    iget-object p1, p1, Llyiahf/vczjk/fp2;->OooO0O0:Llyiahf/vczjk/fz9;

    iget-object v2, p1, Llyiahf/vczjk/fz9;->OooO00o:Llyiahf/vczjk/iv2;

    if-nez v2, :cond_0

    move-object v2, p0

    check-cast v2, Llyiahf/vczjk/fp2;

    iget-object v2, v2, Llyiahf/vczjk/fp2;->OooO0O0:Llyiahf/vczjk/fz9;

    iget-object v2, v2, Llyiahf/vczjk/fz9;->OooO00o:Llyiahf/vczjk/iv2;

    :cond_0
    iget-object v3, p1, Llyiahf/vczjk/fz9;->OooO0O0:Llyiahf/vczjk/hr8;

    if-nez v3, :cond_1

    move-object v3, p0

    check-cast v3, Llyiahf/vczjk/fp2;

    iget-object v3, v3, Llyiahf/vczjk/fp2;->OooO0O0:Llyiahf/vczjk/fz9;

    iget-object v3, v3, Llyiahf/vczjk/fz9;->OooO0O0:Llyiahf/vczjk/hr8;

    :cond_1
    iget-object v4, p1, Llyiahf/vczjk/fz9;->OooO0OO:Llyiahf/vczjk/ls0;

    if-nez v4, :cond_2

    move-object v4, p0

    check-cast v4, Llyiahf/vczjk/fp2;

    iget-object v4, v4, Llyiahf/vczjk/fp2;->OooO0O0:Llyiahf/vczjk/fz9;

    iget-object v4, v4, Llyiahf/vczjk/fz9;->OooO0OO:Llyiahf/vczjk/ls0;

    :cond_2
    iget-object v5, p1, Llyiahf/vczjk/fz9;->OooO0Oo:Llyiahf/vczjk/s78;

    if-nez v5, :cond_3

    move-object v5, p0

    check-cast v5, Llyiahf/vczjk/fp2;

    iget-object v5, v5, Llyiahf/vczjk/fp2;->OooO0O0:Llyiahf/vczjk/fz9;

    iget-object v5, v5, Llyiahf/vczjk/fz9;->OooO0Oo:Llyiahf/vczjk/s78;

    :cond_3
    move-object v6, p0

    check-cast v6, Llyiahf/vczjk/fp2;

    iget-object v6, v6, Llyiahf/vczjk/fp2;->OooO0O0:Llyiahf/vczjk/fz9;

    iget-object v6, v6, Llyiahf/vczjk/fz9;->OooO0o:Ljava/util/Map;

    iget-object p1, p1, Llyiahf/vczjk/fz9;->OooO0o:Ljava/util/Map;

    invoke-static {v6, p1}, Llyiahf/vczjk/lc5;->o0ooOOo(Ljava/util/Map;Ljava/util/Map;)Ljava/util/LinkedHashMap;

    move-result-object v6

    const/16 v7, 0x10

    invoke-direct/range {v1 .. v7}, Llyiahf/vczjk/fz9;-><init>(Llyiahf/vczjk/iv2;Llyiahf/vczjk/hr8;Llyiahf/vczjk/ls0;Llyiahf/vczjk/s78;Ljava/util/LinkedHashMap;I)V

    invoke-direct {v0, v1}, Llyiahf/vczjk/fp2;-><init>(Llyiahf/vczjk/fz9;)V

    return-object v0
.end method

.method public final equals(Ljava/lang/Object;)Z
    .locals 1

    instance-of v0, p1, Llyiahf/vczjk/ep2;

    if-eqz v0, :cond_0

    check-cast p1, Llyiahf/vczjk/ep2;

    check-cast p1, Llyiahf/vczjk/fp2;

    iget-object p1, p1, Llyiahf/vczjk/fp2;->OooO0O0:Llyiahf/vczjk/fz9;

    move-object v0, p0

    check-cast v0, Llyiahf/vczjk/fp2;

    iget-object v0, v0, Llyiahf/vczjk/fp2;->OooO0O0:Llyiahf/vczjk/fz9;

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result p1

    if-eqz p1, :cond_0

    const/4 p1, 0x1

    return p1

    :cond_0
    const/4 p1, 0x0

    return p1
.end method

.method public final hashCode()I
    .locals 1

    move-object v0, p0

    check-cast v0, Llyiahf/vczjk/fp2;

    iget-object v0, v0, Llyiahf/vczjk/fp2;->OooO0O0:Llyiahf/vczjk/fz9;

    invoke-virtual {v0}, Llyiahf/vczjk/fz9;->hashCode()I

    move-result v0

    return v0
.end method

.method public final toString()Ljava/lang/String;
    .locals 4

    sget-object v0, Llyiahf/vczjk/ep2;->OooO00o:Llyiahf/vczjk/fp2;

    invoke-virtual {p0, v0}, Llyiahf/vczjk/ep2;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-eqz v0, :cond_0

    const-string v0, "EnterTransition.None"

    return-object v0

    :cond_0
    move-object v0, p0

    check-cast v0, Llyiahf/vczjk/fp2;

    new-instance v1, Ljava/lang/StringBuilder;

    const-string v2, "EnterTransition: \nFade - "

    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    iget-object v0, v0, Llyiahf/vczjk/fp2;->OooO0O0:Llyiahf/vczjk/fz9;

    iget-object v2, v0, Llyiahf/vczjk/fz9;->OooO00o:Llyiahf/vczjk/iv2;

    const/4 v3, 0x0

    if-eqz v2, :cond_1

    invoke-virtual {v2}, Llyiahf/vczjk/iv2;->toString()Ljava/lang/String;

    move-result-object v2

    goto :goto_0

    :cond_1
    move-object v2, v3

    :goto_0
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v2, ",\nSlide - "

    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    iget-object v2, v0, Llyiahf/vczjk/fz9;->OooO0O0:Llyiahf/vczjk/hr8;

    if-eqz v2, :cond_2

    invoke-virtual {v2}, Llyiahf/vczjk/hr8;->toString()Ljava/lang/String;

    move-result-object v2

    goto :goto_1

    :cond_2
    move-object v2, v3

    :goto_1
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v2, ",\nShrink - "

    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    iget-object v2, v0, Llyiahf/vczjk/fz9;->OooO0OO:Llyiahf/vczjk/ls0;

    if-eqz v2, :cond_3

    invoke-virtual {v2}, Llyiahf/vczjk/ls0;->toString()Ljava/lang/String;

    move-result-object v2

    goto :goto_2

    :cond_3
    move-object v2, v3

    :goto_2
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v2, ",\nScale - "

    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    iget-object v0, v0, Llyiahf/vczjk/fz9;->OooO0Oo:Llyiahf/vczjk/s78;

    if-eqz v0, :cond_4

    invoke-virtual {v0}, Llyiahf/vczjk/s78;->toString()Ljava/lang/String;

    move-result-object v3

    :cond_4
    invoke-virtual {v1, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method
